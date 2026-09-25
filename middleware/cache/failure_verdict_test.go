package cache

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
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
