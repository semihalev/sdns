// Package lease carries a lifetime bound that may be set on two clocks at
// once.
//
// A delegation's lease is a monotonic deadline: it is a TTL counted from the
// moment the referral arrived, and a wall-clock step must not move it. A
// signature's expiration is a wall-clock instant: it ends when the calendar
// says so, whatever the monotonic clock has counted. An answer derived from
// both is bound by both, and the two cannot be folded into one deadline:
// which of them comes first depends on how the wall clock moves after the
// fold, so choosing one at any instant drops the other. A Lease keeps the
// earliest deadline of each kind, and only the question "how long is left
// at now" ever combines them.
package lease

import "time"

// Bound is one deadline and the delegation cache key that supplied it. A
// zero Until is unbounded.
type Bound struct {
	Until time.Time
	Key   uint64
}

// Lease is the earliest monotonic deadline and the earliest wall-clock
// deadline a lifetime has inherited. The zero value is unbounded.
type Lease struct {
	mono Bound
	wall Bound
}

// Of returns the lease of a single deadline. A zero deadline is unbounded.
// Whether it is monotonic is read from the deadline itself: an instant
// derived from time.Now keeps the monotonic reading, one built from a
// calendar value (time.Unix, a UTC conversion) has none.
func Of(until time.Time, key uint64) Lease {
	var l Lease
	l.Fold(until, key)
	return l
}

// Until is Of without a delegation identity.
func Until(until time.Time) Lease { return Of(until, 0) }

// monotonic reports whether t carries a monotonic clock reading. Round(0)
// strips the reading and changes nothing else, so the two differ exactly
// when there was one.
func monotonic(t time.Time) bool { return t != t.Round(0) }

// Monotonic reports whether t carries a monotonic clock reading, the kind
// Of files it under.
func Monotonic(t time.Time) bool { return monotonic(t) }

// Min returns the lease bound by both l and o: the earlier deadline of each
// kind. On equal deadlines l's identity is kept, so an ancestor passed as
// the receiver keeps its identity when a descendant inherits its exact
// deadline.
func (l Lease) Min(o Lease) Lease {
	l.Merge(&o)
	return l
}

// Merge is l = l.Min(*o) in place, for the paths every cache hit takes.
func (l *Lease) Merge(o *Lease) {
	l.mono.fold(o.mono.Until, o.mono.Key)
	l.wall.fold(o.wall.Until, o.wall.Key)
}

// Fold is l = l.Min(Of(until, key)) in place.
func (l *Lease) Fold(until time.Time, key uint64) {
	switch {
	case until.IsZero():
	case monotonic(until):
		l.mono.fold(until, key)
	default:
		l.wall.fold(until, key)
	}
}

// fold keeps the earlier of b and a deadline of the same kind, so Before
// reads the clock both were taken on; b wins a tie.
func (b *Bound) fold(until time.Time, key uint64) {
	if !until.IsZero() && (b.Until.IsZero() || until.Before(b.Until)) {
		*b = Bound{Until: until, Key: key}
	}
}

// IsZero reports whether the lease is unbounded.
func (l Lease) IsZero() bool { return l.mono.Until.IsZero() && l.wall.Until.IsZero() }

// Remaining returns how long the lease has left at now, the shorter of its
// two deadlines, each read on its own clock. bounded is false for an
// unbounded lease, and d is then meaningless.
func (l Lease) Remaining(now time.Time) (d time.Duration, bounded bool) {
	if !l.mono.Until.IsZero() {
		d, bounded = l.mono.Until.Sub(now), true
	}
	if !l.wall.Until.IsZero() {
		if w := l.wall.Until.Sub(now); !bounded || w < d {
			d = w
		}
		bounded = true
	}
	return d, bounded
}

// Expired reports whether a bounded lease has run out at now. An unbounded
// lease never does.
func (l Lease) Expired(now time.Time) bool {
	d, bounded := l.Remaining(now)
	return bounded && d <= 0
}

// Keyed returns the lease with key as the identity of every deadline it
// holds. A delegation read back from the cache vouches for its whole lease
// under its own key, whichever ancestor first supplied the deadline.
func (l Lease) Keyed(key uint64) Lease {
	if !l.mono.Until.IsZero() {
		l.mono.Key = key
	}
	if !l.wall.Until.IsZero() {
		l.wall.Key = key
	}
	return l
}

// Mono returns the monotonic deadline, zero when there is none.
func (l Lease) Mono() Bound { return l.mono }

// Wall returns the wall-clock deadline, zero when there is none.
func (l Lease) Wall() Bound { return l.wall }
