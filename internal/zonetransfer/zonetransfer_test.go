package zonetransfer

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
)

// serveZone answers one SOA probe or AXFR per connection for the given
// zone, streaming the body between the opening and closing apex SOA.
func serveZone(t *testing.T, zone string, body []dns.RR) string {
	t.Helper()
	soa := &dns.SOA{
		Hdr:    dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:     "ns." + zone,
		Mbox:   "admin." + zone,
		Serial: 7, Refresh: 3600, Retry: 900, Expire: 604800, Minttl: 300,
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				co := &dnsclient.Conn{Conn: c}
				req, err := co.ReadMsg()
				if err != nil || len(req.Question) != 1 {
					return
				}
				resp := new(dns.Msg)
				resp.SetReply(req)
				switch req.Question[0].Qtype {
				case dns.TypeSOA:
					resp.Answer = []dns.RR{soa}
				case dns.TypeAXFR:
					resp.Answer = append([]dns.RR{soa}, body...)
					resp.Answer = append(resp.Answer, soa)
				}
				_ = co.WriteMsg(resp)
			}(c)
		}
	}()
	return l.Addr().String()
}

// TestAXFRCarriesTheZoneParameter is the point of the extraction: the
// primitives serve any apex, not the root the first consumer was welded
// to. The whole shape discipline — opener, terminator, dropped closer —
// holds for a policy-feed-shaped zone.
func TestAXFRCarriesTheZoneParameter(t *testing.T) {
	const zone = "feed.example."
	body := []dns.RR{
		&dns.CNAME{Hdr: dns.RR_Header{Name: "bad.example.com." + zone, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "."},
		&dns.A{Hdr: dns.RR_Header{Name: "walled.example.com." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: []byte{192, 0, 2, 1}},
	}
	addr := serveZone(t, zone, body)

	rrs, err := AXFR(context.Background(), addr, zone, 3*time.Second, Limits{MaxRecords: 100, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// Opening SOA + the body; the closing duplicate dropped.
	if len(rrs) != 3 || rrs[0].Header().Rrtype != dns.TypeSOA {
		t.Fatalf("rrs = %v", rrs)
	}

	serial, err := ProbeSerial(context.Background(), addr, zone, 3*time.Second)
	if err != nil || serial != 7 {
		t.Fatalf("probe = %d, %v", serial, err)
	}

	// The same server refuses to be treated as a different apex: the
	// probe for another zone finds no matching SOA.
	if _, err := ProbeSerial(context.Background(), addr, "other.example.", 3*time.Second); err == nil {
		t.Fatal("a probe for the wrong zone answered")
	}
}

// TestAXFRLimitsAreTheCallers pins why Limits is a parameter at all: the
// first consumer's root-sized cap would refuse a legitimate
// multi-million-record policy feed, so the bound belongs to the caller.
func TestAXFRLimitsAreTheCallers(t *testing.T) {
	const zone = "feed.example."
	body := make([]dns.RR, 8)
	for i := range body {
		body[i] = &dns.A{
			Hdr: dns.RR_Header{Name: "r.example." + zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   []byte{192, 0, 2, byte(i + 1)},
		}
	}
	addr := serveZone(t, zone, body)

	if _, err := AXFR(context.Background(), addr, zone, 3*time.Second, Limits{MaxRecords: 4, MaxBytes: 1 << 20}); err != ErrLimit {
		t.Fatalf("tight record cap: err = %v, want ErrLimit", err)
	}
	if _, err := AXFR(context.Background(), addr, zone, 3*time.Second, Limits{MaxRecords: 100, MaxBytes: 16}); err != ErrLimit {
		t.Fatalf("tight byte cap: err = %v, want ErrLimit", err)
	}
	if rrs, err := AXFR(context.Background(), addr, zone, 3*time.Second, Limits{MaxRecords: 100, MaxBytes: 1 << 20}); err != nil || len(rrs) != 9 {
		t.Fatalf("roomy caps: %d rrs, %v", len(rrs), err)
	}
}

func TestSerialNewerWraps(t *testing.T) {
	for _, tc := range []struct {
		a, b uint32
		want bool
	}{
		{1, 2, true},
		{2, 1, false},
		{0xFFFFFFFF, 0, true}, // RFC 1982: the space wraps
		{0, 0xFFFFFFFF, false},
		{5, 5, false},
	} {
		if got := SerialNewer(tc.a, tc.b); got != tc.want {
			t.Errorf("SerialNewer(%d, %d) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestJitterStaysInBand(t *testing.T) {
	const d = 10 * time.Second
	for range 200 {
		j := Jitter(d)
		if j < 9*time.Second || j > 11*time.Second {
			t.Fatalf("jitter %v outside ±10%% of %v", j, d)
		}
	}
	if Jitter(0) != 0 {
		t.Fatal("zero interval must stay zero")
	}
}

func TestNormalizeZoneDedupsToLowestTTL(t *testing.T) {
	mk := func(ttl uint32) dns.RR {
		return &dns.A{
			Hdr: dns.RR_Header{Name: "a.example.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
			A:   []byte{192, 0, 2, 1},
		}
	}
	out := NormalizeZone([]dns.RR{mk(300), mk(60), mk(300)})
	if len(out) != 1 || out[0].Header().Ttl != 60 {
		t.Fatalf("out = %v", out)
	}
}
