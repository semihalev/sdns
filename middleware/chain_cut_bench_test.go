package middleware

import (
	"testing"
	"time"
)

// BenchmarkBoundCutFor pins the cost of folding a bound into the request
// tree. Every cache hit now folds its own lifetime in, so this sits on the
// hottest path in the server and must not allocate.
func BenchmarkBoundCutFor(b *testing.B) {
	var meta ResponseMeta
	deadline := time.Now().Add(time.Minute)

	b.ReportAllocs()
	for i := 0; b.Loop(); i++ {
		// Alternate so both the winning and the losing comparison are
		// measured: a later deadline is discarded, an earlier one replaces.
		meta.BoundCutFor(deadline.Add(time.Duration(i%2)*time.Second), uint64(i))
	}
}
