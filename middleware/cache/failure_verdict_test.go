package cache

import (
	"context"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// A failure recorded as a validation verdict is replayed marked, to the
// resolver's own lookups as to the pipeline; any other failure is not.
func TestFailureReplayCarriesTheVerdict(t *testing.T) {
	for _, tc := range []struct {
		provenance FailureProvenance
		marked     bool
	}{{FailureProvenanceValidation, true}, {FailureProvenance("response"), false}} {
		t.Run(string(tc.provenance), func(t *testing.T) {
			s := NewStore(
				NewPositiveCache(1024, minTTL, maxTTL, &CacheMetrics{}),
				NewNegativeCache(1024, minTTL, time.Hour, &CacheMetrics{}),
				CacheConfig{},
			)
			req := new(dns.Msg)
			req.SetQuestion("bogus.example.", dns.TypeA)
			failed := new(dns.Msg)
			failed.SetRcode(req, dns.RcodeServerFailure)
			s.RecordFailure(failed, netip.Prefix{}, tc.provenance, nil)

			ctx := middleware.WithResponseMeta(context.Background(), new(middleware.ResponseMeta))
			resp, ok := s.GetWithContext(ctx, req)
			if !ok || resp.Rcode != dns.RcodeServerFailure {
				t.Fatalf("replay = %v, %v, want the cached SERVFAIL", resp, ok)
			}
			if got := middleware.IsValidationFailureResponse(ctx, resp); got != tc.marked {
				t.Fatalf("replay marked %v, want %v", got, tc.marked)
			}
		})
	}
}

// Two lookups that missed together complete in either order. A validation
// verdict landing second takes over the active generation's provenance and
// nothing else; a generic failure landing second changes nothing, so the
// verdict, once in, stays.
func TestActiveFailureTakesALateVerdict(t *testing.T) {
	generic := FailureProvenance("response")
	for _, tc := range []struct {
		name          string
		first, second FailureProvenance
	}{
		{"generic first, verdict second", generic, FailureProvenanceValidation},
		{"verdict first, generic second", FailureProvenanceValidation, generic},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock := &failureFakeClock{now: time.Unix(1_000_000, 0)}
			c := newFailureTestCache(t, 64, clock)
			key := failureQuestion("bogus.example.", dns.TypeA)

			first := c.RecordQuestion(key, tc.first, nil)
			clock.Advance(time.Second)
			second := c.RecordQuestion(key, tc.second, nil)
			if second.Provenance != FailureProvenanceValidation {
				t.Fatalf("provenance %q, want the verdict", second.Provenance)
			}
			if !second.RetryAfter.Equal(first.RetryAfter) || second.Streak != first.Streak {
				t.Fatalf("generation moved: retry %v streak %d, was %v and %d",
					second.RetryAfter, second.Streak, first.RetryAfter, first.Streak)
			}
			if hit, ok := c.Lookup(key); !ok || hit.Provenance != FailureProvenanceValidation {
				t.Fatalf("lookup = %+v, %v, want the verdict", hit, ok)
			}
		})
	}
}

// Generic and verdict completions racing into one active generation always
// leave the verdict in it.
func TestConcurrentFailuresKeepTheVerdict(t *testing.T) {
	clock := &failureFakeClock{now: time.Unix(1_000_000, 0)}
	c := newFailureTestCache(t, 64, clock)
	key := failureQuestion("race.example.", dns.TypeA)
	c.RecordQuestion(key, FailureProvenance("response"), nil)

	var wg sync.WaitGroup
	for i := range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			provenance := FailureProvenance("response")
			if i == 17 {
				provenance = FailureProvenanceValidation
			}
			c.RecordQuestion(key, provenance, nil)
		}()
	}
	wg.Wait()
	if hit, ok := c.Lookup(key); !ok || hit.Provenance != FailureProvenanceValidation {
		t.Fatalf("lookup = %+v, %v, want the verdict one racer brought", hit, ok)
	}
}

// Two internal requests for one question, which skip the cache's in-flight
// coalescing as a resolver's sub-queries do, both miss and resolve at once;
// the generic failure is written first, the validation verdict second. The
// replay that follows must still be the verdict.
func TestOverlappingMissesKeepTheVerdict(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer c.Stop()

	arrived := make(chan struct{}, 2)
	release := map[bool]chan struct{}{false: make(chan struct{}), true: make(chan struct{})}
	resolver := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		ctx, req := ch.Materialize(ctx)
		verdict := req.Id == 2
		arrived <- struct{}{}
		<-release[verdict]
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeServerFailure)
		if verdict {
			middleware.MarkValidationFailureResponse(ctx, resp)
		}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	ask := func(id uint16) *dns.Msg {
		req := new(dns.Msg)
		req.SetQuestion("overlap.example.", dns.TypeA)
		req.Id = id
		// The internal-query sentinel address, as a Queryer's writer has.
		writer := mock.NewWriter("udp", "127.0.0.255:0")
		ch := middleware.NewChain([]middleware.Handler{c, resolver})
		ch.Reset(writer, req)
		ch.Next(context.Background())
		return writer.Msg()
	}

	done := make(chan struct{}, 2)
	for _, id := range []uint16{1, 2} {
		go func() { ask(id); done <- struct{}{} }()
	}
	<-arrived
	<-arrived // both missed and are resolving
	close(release[false])
	<-done // the generic failure is admitted first
	close(release[true])
	<-done

	req := new(dns.Msg)
	req.SetQuestion("overlap.example.", dns.TypeA)
	ctx := middleware.WithResponseMeta(context.Background(), new(middleware.ResponseMeta))
	resp, ok := c.store.GetWithContext(ctx, req)
	if !ok || resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("replay = %v, %v, want the cached SERVFAIL", resp, ok)
	}
	if !middleware.IsValidationFailureResponse(ctx, resp) {
		t.Fatal("the replay lost the verdict the second completion brought")
	}
}

// Two first records for a question no generation holds yet: one has found
// the slot empty and is held there while the other installs its generation.
// Whichever order they land in, the verdict one of them carries survives in
// the single generation left.
func TestRacingFirstRecordsKeepTheVerdict(t *testing.T) {
	generic := FailureProvenance("response")
	for _, held := range []FailureProvenance{generic, FailureProvenanceValidation} {
		t.Run("held "+string(held), func(t *testing.T) {
			clock := &failureFakeClock{now: time.Unix(1_000_000, 0)}
			c := newFailureTestCache(t, 64, clock)
			key := failureQuestion("first.example.", dns.TypeA)

			reached, release := make(chan struct{}), make(chan struct{})
			var once sync.Once
			c.beforeFirstRecord = func(p FailureProvenance) {
				if p == held {
					once.Do(func() { close(reached); <-release })
				}
			}
			other := FailureProvenanceValidation
			if held == FailureProvenanceValidation {
				other = generic
			}

			done := make(chan struct{})
			go func() { c.RecordQuestion(key, held, nil); close(done) }()
			<-reached // held has seen the slot empty
			c.RecordQuestion(key, other, nil)
			close(release)
			<-done

			hit, ok := c.Lookup(key)
			if !ok || hit.Provenance != FailureProvenanceValidation || hit.Streak != 1 {
				t.Fatalf("lookup = %+v, %v, want one generation holding the verdict", hit, ok)
			}
		})
	}
}
