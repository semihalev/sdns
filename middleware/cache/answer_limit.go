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

// inherit takes over from's state, so an entry replacing another under the
// same key, a refresh, starts from the bucket its predecessor left rather
// than a full one.
func (l *answerLimit) inherit(from *answerLimit) { l.tat.Store(from.tat.Load()) }
