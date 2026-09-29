package cache

import (
	"sync"
	"sync/atomic"
	"time"
)

// The expiry index finds the values whose time has come without walking
// the cache. Each insert that states an end files its key, 8 bytes, in the
// bucket of that end, and marks the value with the bucket (ExpiryMark);
// Expire opens only the buckets whose time has passed. A key there counts
// only while its value still carries the bucket's mark: a record left
// behind by a replaced, removed or refiled value is stale and skipped, so
// a value has one live record however often its key was written.
//
// A live record whose value is not dead yet is filed again at the end the
// owner reports now, never dropped: a record that fires early, because a
// wall clock stepped back or an end was estimated short, only comes round
// again. An end beyond the ring is filed in the ring's last bucket and
// comes round the same way.
//
// Stale records are dropped as their buckets fire, and when they outnumber
// the cache's values by more than compactSlack, Expire compacts the ring
// down to the live ones, which bounds the index by the cache's occupancy.
// Filing reads no clock: an end is placed against the index's epoch, and
// the ring against the first bucket still to fire.
const (
	expiryBuckets = 256
	expiryShards  = 16

	// expiryKeepCap is the largest bucket slice kept for reuse once its
	// bucket has fired; a larger one, from a burst, goes to the GC.
	expiryKeepCap = 1024
)

// compactSlack is how many records beyond twice the cache's values the
// index holds before Expire compacts it.
var compactSlack int64 = 4096

// Verdict is an owner's judgement of a value an expiry record points at.
type Verdict uint8

const (
	// Alive: the value is not dead yet. Its record is filed again for the
	// end the owner reports, or retired when that is the zero time, no end.
	Alive Verdict = iota
	// Dead: remove the value.
	Dead
	// Busy: the owner cannot decide now, look again a bucket later.
	Busy
)

// ExpiryMark is a word a value lends the expiry index: bits 1 to 31 name
// the bucket its live record is in, zero for none. Bit 0 belongs to the
// owner, through Flag and its siblings, and the index never changes it.
// A value is marked for one key: two keys must not share it.
type ExpiryMark struct {
	w atomic.Uint32
}

// Flag reports the owner's bit.
func (m *ExpiryMark) Flag() bool { return m.w.Load()&1 != 0 }

// SetFlag sets the owner's bit, leaving the mark.
func (m *ExpiryMark) SetFlag(v bool) {
	for {
		old := m.w.Load()
		next := old &^ 1
		if v {
			next |= 1
		}
		if old == next || m.w.CompareAndSwap(old, next) {
			return
		}
	}
}

// CompareAndSwapFlag sets the owner's bit to next if it is old, leaving
// the mark, and reports whether it did.
func (m *ExpiryMark) CompareAndSwapFlag(old, next bool) bool {
	for {
		w := m.w.Load()
		if (w&1 != 0) != old {
			return false
		}
		n := w &^ 1
		if next {
			n |= 1
		}
		if m.w.CompareAndSwap(w, n) {
			return true
		}
	}
}

// markOf encodes bucket b as a mark: never zero, 31 bits.
func markOf(b int64) uint32 { return uint32(b%(1<<31-1)) + 1 } //nolint:gosec // reduced below 2^31

func (m *ExpiryMark) mark() uint32 { return m.w.Load() >> 1 }

func (m *ExpiryMark) setMark(mark uint32) {
	for {
		old := m.w.Load()
		if m.w.CompareAndSwap(old, mark<<1|old&1) {
			return
		}
	}
}

type expiryShard struct {
	mu   sync.Mutex
	next int64 // the first bucket not yet fired
	ring [expiryBuckets][]uint64
}

type expiryIndex struct {
	gran    int64     // nanoseconds a bucket spans
	epoch   time.Time // ends are filed as nanoseconds since it
	now     func() time.Time
	records atomic.Int64 // keys in the ring, stale ones included
	run     sync.Mutex   // one Expire at a time
	shards  [expiryShards]expiryShard
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

// file marks m with the bucket of at, nanoseconds since the epoch, and
// files key there. An end already past is due in the first bucket still
// to fire; one beyond the ring waits in its last bucket and is filed again
// from there.
func (x *expiryIndex) file(key uint64, m *ExpiryMark, at int64) {
	sh := &x.shards[key%expiryShards]
	sh.mu.Lock()
	b := min(max(at/x.gran, sh.next), sh.next+expiryBuckets-1)
	m.setMark(markOf(b))
	i := b % expiryBuckets
	sh.ring[i] = append(sh.ring[i], key)
	sh.mu.Unlock()
	x.records.Add(1)
}

// track files key for until, or unmarks m for the zero time, no end.
func (x *expiryIndex) track(key uint64, m *ExpiryMark, until time.Time) {
	if until.IsZero() {
		m.setMark(0)
		return
	}
	x.file(key, m, int64(until.Sub(x.epoch)))
}

// AddUntil is Add for a value that can be dead by until, filing its key
// in the expiry index. An end that comes early only costs a second look;
// one that comes late delays the removal. The zero time files nothing,
// for a value with no end.
func (c *Cache[V]) AddUntil(key uint64, value V, until time.Time) {
	c.data.SetWithCap(key, value, c.maxSize)
	if c.exp != nil {
		c.exp.track(key, c.mark(value), until)
	}
}

// AddIfAbsentUntil is AddIfAbsent filing the key as AddUntil does, when
// value was stored.
func (c *Cache[V]) AddIfAbsentUntil(key uint64, value V, until time.Time) bool {
	if !c.AddIfAbsent(key, value) {
		return false
	}
	if c.exp != nil {
		c.exp.track(key, c.mark(value), until)
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
		c.exp.track(key, c.mark(value), until)
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
// reports the value's fate and, for Alive, the end it has now. A cache
// built without an expiry index has nothing to fire.
func (c *Cache[V]) Expire(judge func(V) (Verdict, time.Time)) (removed int) {
	x := c.exp
	if x == nil {
		return 0
	}
	x.run.Lock()
	defer x.run.Unlock()
	if x.records.Load() > 2*int64(c.Len())+compactSlack {
		c.compact()
	}
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
			sh.next = b + 1
			sh.mu.Unlock()
			x.records.Add(-int64(len(keys)))

			removed += c.fire(keys, markOf(b), due, judge)

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

// fire judges the value each live record of a bucket, the one marked
// mark, points at. A value that stays is filed again no sooner than due,
// the first bucket this Expire does not fire, so a value judged alive past
// its own end is asked once a pass, not in every bucket a pass that fell
// behind still has to fire.
func (c *Cache[V]) fire(keys []uint64, mark uint32, due int64, judge func(V) (Verdict, time.Time)) (removed int) {
	m := c.data.data
	x := c.exp
	for _, key := range keys {
		seg := m.getSegment(key)
		seg.rwlock.Lock()
		v, ok := seg.data.Get(key)
		if !ok || c.mark(v).mark() != mark {
			seg.rwlock.Unlock()
			continue
		}
		verdict, until := judge(v)
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
			x.file(key, c.mark(v), (due+1)*x.gran)
		case until.IsZero():
			c.mark(v).setMark(0)
		default:
			x.file(key, c.mark(v), max(int64(until.Sub(x.epoch)), due*x.gran))
		}
	}
	return removed
}

// compact drops the stale records: each shard's ring is taken whole and
// only the records whose values still carry their bucket's mark are filed
// back. It runs under Expire's lock, so no bucket fires meanwhile; inserts
// go on into the emptied ring.
func (c *Cache[V]) compact() {
	x := c.exp
	m := c.data.data
	for s := range x.shards {
		sh := &x.shards[s]
		sh.mu.Lock()
		ring := sh.ring
		next := sh.next
		sh.ring = [expiryBuckets][]uint64{}
		sh.mu.Unlock()

		var dropped int64
		for i := range ring {
			// Slot i holds the one bucket in [next, next+expiryBuckets) that
			// is i modulo the ring.
			b := next + (int64(i)-next%expiryBuckets+expiryBuckets)%expiryBuckets
			mark := markOf(b)
			kept := ring[i][:0]
			for _, key := range ring[i] {
				if v, ok := m.Get(key); ok && c.mark(v).mark() == mark {
					kept = append(kept, key)
				} else {
					dropped++
				}
			}
			if len(kept) == 0 {
				continue
			}
			sh.mu.Lock()
			sh.ring[i] = append(sh.ring[i], kept...)
			sh.mu.Unlock()
		}
		x.records.Add(-dropped)
	}
}
