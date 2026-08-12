package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

func TestP6RFC8198KillSwitchDisablesAdmissionAndSynthesis(t *testing.T) {
	disabled := false
	cache := New(&config.Config{
		CacheSize: 1024,
		Expire:    300,
		DNSSEC:    "on",
		RFC8198:   &disabled,
	})
	defer cache.Stop()

	now := time.Now().UTC()
	fixture := newP6NSEC3NXDOMAINFixture(t, now, p6NSEC3Denied)
	if cache.store.RecordDenialProof(
		fixture.msg,
		p6NSEC3Zone,
		middleware.ValidatedNegativeProofNSEC3,
		time.Time{},
	) {
		t.Fatal("RFC 8198 kill switch admitted a shared NSEC3 proof")
	}

	// Plant state below the Store policy seam so consumption is tested
	// independently from the admission rejection above.
	if !cache.store.denialProofs.record(
		fixture.msg,
		p6NSEC3Zone,
		time.Time{},
	) {
		t.Fatal("could not plant lower-level NSEC3 proof state")
	}

	work := &p6NSEC3Work{limit: 8}
	req := denialProofTestRequest(p6NSEC3Denied, dns.TypeA, true)
	if got, kind, zone, _, ok := cache.store.LookupDenialProof(req, work); ok ||
		got != nil ||
		kind != middleware.ValidatedNegativeProofUnknown ||
		zone != "" {
		t.Fatalf(
			"disabled RFC 8198 lookup consumed proof: response=%#v kind=%d zone=%q hit=%v",
			got,
			kind,
			zone,
			ok,
		)
	}
	if work.attempts != 0 || work.calls != 0 {
		t.Fatalf("disabled RFC 8198 lookup hashed: attempts=%d calls=%d",
			work.attempts,
			work.calls,
		)
	}
	if got, ok := cache.store.GetWithContext(context.Background(), req); ok || got != nil {
		t.Fatalf("disabled RFC 8198 Store.GetWithContext consumed proof: %#v", got)
	}

	limiter := newP6CountingCryptoLimiter(8)
	cache.SetDNSSECCryptoLimiter(limiter)
	downstreamCalls := 0
	downstream := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		downstreamCalls++
		_ = ch.Writer.WriteMsg(aggressiveNegativePositiveResponse(ch.Request))
		ch.Cancel()
	})
	got := aggressiveNegativeExchange(t, context.Background(), cache, downstream, req)
	if got.Rcode != dns.RcodeSuccess || len(got.Answer) != 1 {
		t.Fatalf("disabled RFC 8198 did not fall through: %#v", got)
	}
	if limiter.calls.Load() != 0 {
		t.Fatalf("disabled RFC 8198 middleware path attempted %d hashes",
			limiter.calls.Load(),
		)
	}
	if downstreamCalls != 1 {
		t.Fatalf("downstream calls = %d, want 1", downstreamCalls)
	}
}

func TestP6RFC8198KillSwitchLeavesRFC8020Enabled(t *testing.T) {
	disabled := false
	cache := New(&config.Config{
		CacheSize: 1024,
		Expire:    300,
		DNSSEC:    "on",
		RFC8198:   &disabled,
	})
	defer cache.Stop()

	fixture := newP6NSEC3NXDOMAINFixture(t, time.Now().UTC(), p6NSEC3Denied)
	if !cache.store.RecordNXDomainCut(
		fixture.msg,
		p6NSEC3Denied,
		p6NSEC3Zone,
		time.Time{},
	) {
		t.Fatal("RFC 8198 kill switch unexpectedly disabled RFC 8020 admission")
	}

	req := denialProofTestRequest("child."+p6NSEC3Denied, dns.TypeA, true)
	got, ok := cache.store.GetWithContext(context.Background(), req)
	if !ok || got == nil || got.Rcode != dns.RcodeNameError {
		t.Fatalf("RFC 8020 lookup with RFC 8198 disabled = %#v, hit=%v", got, ok)
	}
}
