package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// stubHitStore implements middleware.Store and always returns the
// pre-configured response on Get — exercises the cache-hit early
// return in subQuery without needing a running resolver.
type stubHitStore struct {
	resp *dns.Msg
	sets int
}

func (s *stubHitStore) Get(req *dns.Msg) (*dns.Msg, bool) {
	if s.resp == nil {
		return nil, false
	}
	return s.resp.Copy(), true
}

func (s *stubHitStore) SetFromResponse(resp *dns.Msg, keyCD bool) {
	s.sets++
}

// TestSubQueryReturnsCacheHit pins that subQuery short-circuits on
// store.Get success — no call to r.resolve, no authoritative
// dispatch. The DS/DNSKEY hot path relies on this: once the first
// client query primes the cache, subsequent validations of the
// same zone skip the full recursion.
func TestSubQueryReturnsCacheHit(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeDS)

	reply := new(dns.Msg)
	reply.SetReply(req)
	reply.Answer = []dns.RR{&dns.DS{
		Hdr:        dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDS, Class: dns.ClassINET, Ttl: 300},
		KeyTag:     12345,
		Algorithm:  8,
		DigestType: 2,
		Digest:     "abcdef",
	}}

	hit := &stubHitStore{resp: reply}
	r := &Resolver{}
	var s middleware.Store = hit
	r.store.Store(&s)

	got, err := r.subQuery(context.Background(), req)
	if err != nil {
		t.Fatalf("subQuery returned err on cache hit: %v", err)
	}
	if got == nil {
		t.Fatal("subQuery returned nil msg on cache hit")
	}
	if len(got.Answer) != 1 {
		t.Fatalf("got %d answers, want 1", len(got.Answer))
	}
	if hit.sets != 0 {
		t.Fatalf("store.SetFromResponse was called %d times on a hit; must be 0", hit.sets)
	}
}
