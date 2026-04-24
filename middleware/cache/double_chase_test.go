package cache

import (
	"context"
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// stubQueryer records every Query call and returns pre-registered
// responses keyed by question name.
type stubQueryer struct {
	responses map[string]*dns.Msg
	calls     int
}

func (q *stubQueryer) Query(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	q.calls++
	if len(req.Question) == 0 {
		return nil, nil
	}
	if resp, ok := q.responses[req.Question[0].Name]; ok {
		// Copy so mutations from additionalAnswer don't bleed back
		// into the stored response.
		return resp.Copy(), nil
	}
	m := new(dns.Msg)
	m.SetReply(req)
	m.Rcode = dns.RcodeServerFailure
	return m, nil
}

// TestAdditionalAnswerStopsOnFullChain pins the reviewer's P2 fix:
// when the inner queryer returns a response that already contains the
// final qtype alongside the CNAME (common when a prior direct query
// fully resolved the CNAME chain and cached it as one entry), the
// outer additionalAnswer loop must stop. The pre-fix path re-queried
// the CNAME target from the cache and appended the same final record
// a second time.
func TestAdditionalAnswerStopsOnFullChain(t *testing.T) {
	cfg := &config.Config{CacheSize: 1024, Expire: 300}
	c := New(cfg)
	defer c.Stop()

	// Stub queryer returns b.example with a full CNAME+A response —
	// simulating the state where a prior client query for b.example
	// populated its cache entry with the chased chain.
	bResp := new(dns.Msg)
	bResp.SetQuestion("b.example.", dns.TypeA)
	bResp.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "b.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "c.example.",
		},
		&dns.A{
			Hdr: dns.RR_Header{Name: "c.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP("192.0.2.1").To4(),
		},
	}
	q := &stubQueryer{responses: map[string]*dns.Msg{"b.example.": bResp}}
	c.queryer = q

	// Outer response as if the resolver returned just [CNAME a→b].
	outer := new(dns.Msg)
	outer.SetQuestion("a.example.", dns.TypeA)
	outer.Answer = []dns.RR{
		&dns.CNAME{
			Hdr:    dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: "b.example.",
		},
	}

	result := c.additionalAnswer(context.Background(), outer)

	aCount := 0
	for _, rr := range result.Answer {
		if _, ok := rr.(*dns.A); ok {
			aCount++
		}
	}
	if aCount != 1 {
		t.Errorf("want exactly 1 final A record in merged response, got %d (answer=%v)", aCount, result.Answer)
	}
	if q.calls != 1 {
		t.Errorf("want exactly 1 internal exchange call (outer chase only), got %d", q.calls)
	}
}
