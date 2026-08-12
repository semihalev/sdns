package middleware

import (
	"testing"
	"time"
)

// Every cache hit folds its own lifetime into the request tree, so BoundCutFor
// sits on the hottest path in the server. The two outcomes are measured apart
// because they do different work: a losing deadline leaves under the lock
// immediately, a winning one writes.
func BenchmarkBoundCutFor(b *testing.B) {
	base := time.Now().Add(time.Minute)

	b.Run("losing", func(b *testing.B) {
		var meta ResponseMeta
		meta.BoundCutFor(base, 1)
		later := base.Add(time.Second)

		b.ReportAllocs()
		for b.Loop() {
			meta.BoundCutFor(later, 2)
		}
	})

	b.Run("winning", func(b *testing.B) {
		var meta ResponseMeta
		// Each call moves the deadline earlier, so every one of them writes.
		deadline := base.Add(time.Duration(b.N+1) * time.Nanosecond)

		b.ReportAllocs()
		for b.Loop() {
			deadline = deadline.Add(-time.Nanosecond)
			meta.BoundCutFor(deadline, 3)
		}
	})

	// The resolver fans out into concurrent sub-queries that share one
	// request meta, which is why the value is guarded at all.
	b.Run("contended", func(b *testing.B) {
		var meta ResponseMeta
		meta.BoundCutFor(base, 1)
		later := base.Add(time.Second)

		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				meta.BoundCutFor(later, 2)
			}
		})
	})
}
