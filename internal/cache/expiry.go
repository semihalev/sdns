package cache

import (
	"math"
	"sync"
	"time"
)

// The expiry index finds the values whose time has come without walking
// the cache. Each insert that states a lifetime files its key, 8 bytes,
// in the bucket of the instant its value can be dead by; Expire opens only
// the buckets whose time has passed and asks the owner about each key
// there. The index holds keys, not values: a record outlives the value it
// was filed for when that value is replaced or removed, and the owner's
// verdict on whatever the key now holds sorts that out.
//
// Buckets form a ring of expiryBuckets slots, gran apart, in expiryShards
// independent shards so writers rarely meet. A lifetime beyond the ring
// goes to the shard's far list, which is filed again once per turn of the
// ring.
const (
	expiryBuckets = 256
	expiryShards  = 16

	// expiryKeepCap is the largest bucket slice kept for reuse once its
	// bucket has fired; a larger one, from a burst, goes to the GC.
	expiryKeepCap = 1024
)

// Verdict is an owner's judgement of a value an expiry record points at.
type Verdict uint8

const (
	// Alive: the value is not dead yet. A ring record is dropped, the
	// value's own record covers it (see AddFor); a far record is filed
	// again at the lifetime the owner reports.
	Alive Verdict = iota
	// Dead: remove the value.
	Dead
	// Busy: the owner cannot decide now, look again a bucket later.
	Busy
)

type expiryShard struct {
	mu   sync.Mutex
	next int64 // the first bucket not yet fired
	ring [expiryBuckets][]uint64
	far  []uint64
}

type expiryIndex struct {
	gran   int64 // nanoseconds a bucket spans
	now    func() int64
	run    sync.Mutex // one Expire at a time
	shards [expiryShards]expiryShard
}

func newExpiryIndex(horizon time.Duration) *expiryIndex {
	gran := int64(horizon) / expiryBuckets
	if gran < int64(time.Second) {
		gran = int64(time.Second)
	}
	epoch := time.Now()
	return &expiryIndex{
		gran: gran,
		now:  func() int64 { return int64(time.Since(epoch)) },
	}
}

// Forever is the lifetime of a value with no end: AddFor files nothing
// for it.
const Forever = time.Duration(math.MaxInt64)

// add files key to fire once life has passed. A life already over, one
// computed from a deadline that passed on the way here, is due now.
func (x *expiryIndex) add(key uint64, life time.Duration) {
	if life == Forever {
		return
	}
	life = max(life, 0)
	sh := &x.shards[key%expiryShards]
	now := x.now()
	sh.mu.Lock()
	// The bucket that holds the instant life ends: firing it, which waits
	// for its whole span to pass, finds the value dead.
	b := sh.next + expiryBuckets // far unless it fits
	if int64(life) < expiryBuckets*x.gran {
		b = max((now+int64(life))/x.gran, sh.next)
	}
	if b-sh.next >= expiryBuckets {
		sh.far = append(sh.far, key)
	} else {
		i := b % expiryBuckets
		sh.ring[i] = append(sh.ring[i], key)
	}
	sh.mu.Unlock()
}

// AddFor is Add for a value that can be dead by life from now, filing its
// key in the expiry index. life must be an upper bound: a value the
// verdict finds alive when its own record fires is taken for a replaced
// one and is left to eviction. Forever files nothing, for a value with no
// end.
func (c *Cache[V]) AddFor(key uint64, value V, life time.Duration) {
	c.data.SetWithCap(key, value, c.maxSize)
	if c.exp != nil {
		c.exp.add(key, life)
	}
}

// AddIfAbsentFor is AddIfAbsent filing the key as AddFor does, when value
// was stored.
func (c *Cache[V]) AddIfAbsentFor(key uint64, value V, life time.Duration) bool {
	if !c.AddIfAbsent(key, value) {
		return false
	}
	if c.exp != nil {
		c.exp.add(key, life)
	}
	return true
}

// CompareAndSwapFor is CompareAndSwap filing the key as AddFor does, when
// value was stored.
func (c *Cache[V]) CompareAndSwapFor(key uint64, old, value V, life time.Duration) bool {
	if !c.CompareAndSwap(key, old, value) {
		return false
	}
	if c.exp != nil {
		c.exp.add(key, life)
	}
	return true
}

// SetExpiryClock replaces the clock the expiry index files and fires by,
// time since some fixed start, for tests that move time by hand. It must
// be set before the first insert.
func (c *Cache[V]) SetExpiryClock(now func() time.Duration) {
	if c.exp != nil {
		c.exp.now = func() int64 { return int64(now()) }
	}
}

// Expire fires every bucket whose time has passed and returns how many
// values it removed. judge runs under the key's segment write lock, one
// key per hold: it must be quick and must not touch this cache. It
// reports the value's fate and, for Alive, how long it has left. A cache
// built without an expiry index has nothing to fire.
func (c *Cache[V]) Expire(judge func(V) (Verdict, time.Duration)) (removed int) {
	x := c.exp
	if x == nil {
		return 0
	}
	x.run.Lock()
	defer x.run.Unlock()
	due := x.now() / x.gran // every bucket before it has passed
	for s := range x.shards {
		sh := &x.shards[s]
		for {
			sh.mu.Lock()
			if sh.next >= due {
				sh.mu.Unlock()
				break
			}
			b := sh.next
			i := b % expiryBuckets
			keys := sh.ring[i]
			sh.ring[i] = nil
			var far []uint64
			if i == 0 {
				far, sh.far = sh.far, nil
			}
			sh.next = b + 1
			sh.mu.Unlock()

			removed += c.fire(keys, false, judge)
			removed += c.fire(far, true, judge)

			if cap(keys) <= expiryKeepCap {
				sh.mu.Lock()
				if sh.ring[i] == nil {
					sh.ring[i] = keys[:0]
				}
				sh.mu.Unlock()
			}
		}
	}
	return removed
}

// fire judges the value each key holds now.
func (c *Cache[V]) fire(keys []uint64, far bool, judge func(V) (Verdict, time.Duration)) (removed int) {
	m := c.data.data
	for _, key := range keys {
		seg := m.getSegment(key)
		seg.rwlock.Lock()
		v, ok := seg.data.Get(key)
		if !ok {
			seg.rwlock.Unlock()
			continue
		}
		verdict, left := judge(v)
		if verdict == Dead {
			if seg.data.Del(key) {
				m.count.Add(-1)
				removed++
			}
			seg.rwlock.Unlock()
			continue
		}
		seg.rwlock.Unlock()
		switch {
		case verdict == Busy:
			c.exp.add(key, time.Duration(c.exp.gran))
		case far:
			c.exp.add(key, left)
		}
	}
	return removed
}
