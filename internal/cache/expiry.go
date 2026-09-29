package cache

import (
	"sync"
	"time"
)

// The expiry index finds the values whose time has come without walking
// the cache. Each insert that states an end files its key, 8 bytes, in the
// bucket of the instant its value can be dead by; Expire opens only the
// buckets whose time has passed and asks the owner about each key there.
// The index holds keys, not values: a record outlives the value it was
// filed for when that value is replaced or removed, and the owner's
// verdict on whatever the key now holds sorts that out.
//
// Buckets form a ring of expiryBuckets slots, gran apart, in expiryShards
// independent shards so writers rarely meet. An end beyond the ring goes
// to the shard's far list, which is filed again once per turn of the ring.
// Filing reads no clock: an end is placed against the index's epoch, and
// the ring against the first bucket still to fire.
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
	// value's own record covers it (see AddUntil); a far record is filed
	// again at the time the owner reports it has left, or dropped when
	// that is not positive, for a value with no end.
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
	gran   int64     // nanoseconds a bucket spans
	epoch  time.Time // ends are filed as nanoseconds since it
	now    func() time.Time
	run    sync.Mutex // one Expire at a time
	shards [expiryShards]expiryShard
}

func newExpiryIndex(horizon time.Duration) *expiryIndex {
	gran := int64(horizon) / expiryBuckets
	if gran < int64(time.Second) {
		gran = int64(time.Second)
	}
	return &expiryIndex{
		gran:  gran,
		epoch: time.Now(),
		now:   time.Now,
	}
}

// add files key to fire once at, nanoseconds since the epoch, has passed.
// An end already past is due in the first bucket still to fire.
func (x *expiryIndex) add(key uint64, at int64) {
	sh := &x.shards[key%expiryShards]
	sh.mu.Lock()
	// The bucket that holds at: firing it, which waits for its whole span
	// to pass, finds the value dead.
	b := max(at/x.gran, sh.next)
	if b-sh.next >= expiryBuckets {
		sh.far = append(sh.far, key)
	} else {
		i := b % expiryBuckets
		sh.ring[i] = append(sh.ring[i], key)
	}
	sh.mu.Unlock()
}

// addUntil files key for until; the zero time, no end, files nothing.
// Reading a monotonic until against the epoch is arithmetic, not a clock
// read. A wall-clock until is placed by the wall clock, so a wall clock
// stepped back after filing fires its record early: the value is found
// alive, the record dropped, and the value left to eviction.
func (x *expiryIndex) addUntil(key uint64, until time.Time) {
	if until.IsZero() {
		return
	}
	x.add(key, int64(until.Sub(x.epoch)))
}

// AddUntil is Add for a value that can be dead by until, filing its key
// in the expiry index. until must be an upper bound: a value the verdict
// finds alive when its own record fires is taken for a replaced one and is
// left to eviction. The zero time files nothing, for a value with no end.
func (c *Cache[V]) AddUntil(key uint64, value V, until time.Time) {
	c.data.SetWithCap(key, value, c.maxSize)
	if c.exp != nil {
		c.exp.addUntil(key, until)
	}
}

// AddIfAbsentUntil is AddIfAbsent filing the key as AddUntil does, when
// value was stored.
func (c *Cache[V]) AddIfAbsentUntil(key uint64, value V, until time.Time) bool {
	if !c.AddIfAbsent(key, value) {
		return false
	}
	if c.exp != nil {
		c.exp.addUntil(key, until)
	}
	return true
}

// CompareAndSwapUntil is CompareAndSwap filing the key as AddUntil does,
// when value was stored.
func (c *Cache[V]) CompareAndSwapUntil(key uint64, old, value V, until time.Time) bool {
	if !c.CompareAndSwap(key, old, value) {
		return false
	}
	if c.exp != nil {
		c.exp.addUntil(key, until)
	}
	return true
}

// SetExpiryClock replaces the clock Expire fires by, for tests that move
// time by hand.
func (c *Cache[V]) SetExpiryClock(now func() time.Time) {
	if c.exp != nil {
		c.exp.now = now
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
	now := int64(x.now().Sub(x.epoch))
	due := now / x.gran // every bucket before it has passed
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

			removed += c.fire(keys, false, now, judge)
			removed += c.fire(far, true, now, judge)

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
func (c *Cache[V]) fire(keys []uint64, far bool, now int64, judge func(V) (Verdict, time.Duration)) (removed int) {
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
			c.exp.add(key, now+c.exp.gran)
		case far && left > 0:
			c.exp.add(key, now+int64(left))
		}
	}
	return removed
}
