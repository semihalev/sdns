package cache

import (
	"sync/atomic"
	"time"
)

// limitEpoch anchors the answer limit's clock. Its readings are
// nanoseconds since this instant on the monotonic clock, so a step of the
// wall clock moves no answer's bucket.
var limitEpoch = time.Now()

func limitNow() int64 { return int64(time.Since(limitEpoch)) }

// answerLimit is one cached answer's own rate limit, a generic cell rate
// algorithm whose whole state is one word: the instant, in limitNow's
// nanoseconds, at which the bucket would be full again. At a rate of r a
// second with a burst of r, each answer moves that instant 1/r of a second
// on, and one that would carry it more than a second past now is refused.
//
// Every answer keeps its own, so a flood on one name drains no other's,
// and charging one is a load and a compare-and-swap with no lock and no
// allocation. The zero value is a full bucket.
type answerLimit struct{ tat atomic.Int64 }

// allow charges one answer at rate, refusing it when the bucket is empty.
func (l *answerLimit) allow(rate int32, now int64) bool {
	step := int64(time.Second) / int64(rate)
	for {
		tat := l.tat.Load()
		next := max(tat, now) + step
		if next-now > int64(time.Second) {
			return false
		}
		if l.tat.CompareAndSwap(tat, next) {
			return true
		}
	}
}

// closedTAT marks the bucket of an entry being replaced, which grants
// nothing. It lies far enough ahead to refuse every charge, and far enough
// from the int64 limit that allow's arithmetic on it cannot overflow.
const closedTAT = int64(1) << 62

// carryLimit hands entry the answer limit of old, the entry it replaces
// under the same question, across publish, the store write that puts
// entry in old's place and reports whether it did. old is closed first,
// taking its state in the same compare and swap, and entry is published
// holding that state, so at every instant at most one of the two grants
// and a question never has two buckets. A query charging old while
// publish runs is refused.
//
// Only one writer can close old. Another that finds it closed reports
// false without publishing, to read the key again once the first is done;
// a failed publish reopens old as it was.
func carryLimit(entry, old *CacheEntry, publish func() bool) bool {
	if entry == old {
		return publish()
	}
	var tat int64
	for {
		tat = old.limit.tat.Load()
		if tat == closedTAT {
			return false
		}
		if old.limit.tat.CompareAndSwap(tat, closedTAT) {
			break
		}
	}
	own := entry.limit.tat.Load()
	entry.limit.tat.Store(max(own, tat))
	if !publish() {
		entry.limit.tat.Store(own)
		old.limit.tat.Store(tat)
		return false
	}
	return true
}
