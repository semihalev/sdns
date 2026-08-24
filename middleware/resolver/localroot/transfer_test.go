package localroot

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
)

// axfrServer serves one AXFR of rrs on a loopback TCP listener: the apex SOA
// first, the body split across two envelopes, the closing SOA last — the
// shape a real transfer host produces.
func axfrServer(t *testing.T, rrs []dns.RR) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	var soa dns.RR
	body := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeSOA && dns.CanonicalName(rr.Header().Name) == "." {
			soa = rr
			continue
		}
		body = append(body, rr)
	}
	if soa == nil {
		t.Fatal("test zone has no apex SOA")
	}

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
				reply := func(rrs []dns.RR) {
					m := new(dns.Msg)
					m.SetReply(req)
					m.Answer = rrs
					_ = co.WriteMsg(m)
				}
				switch req.Question[0].Qtype {
				case dns.TypeSOA:
					reply([]dns.RR{soa})
				case dns.TypeAXFR:
					half := len(body) / 2
					reply(append([]dns.RR{soa}, body[:half]...))
					reply(body[half:])
					reply([]dns.RR{soa})
				}
			}(c)
		}
	}()
	return l.Addr().String()
}

func TestAXFRRoundTrip(t *testing.T) {
	root := buildTestRoot(t)
	addr := axfrServer(t, root.rrs)

	got, err := axfr(context.Background(), addr, 5*time.Second)
	if err != nil {
		t.Fatalf("axfr: %v", err)
	}
	if len(got) != len(root.rrs) {
		t.Fatalf("transfer carried %d records, want %d", len(got), len(root.rrs))
	}
	if err := verifyZone(got, root.anchors); err != nil {
		t.Fatalf("transferred zone does not verify: %v", err)
	}

	serial, err := probeSerial(context.Background(), addr, 5*time.Second)
	if err != nil {
		t.Fatalf("probeSerial: %v", err)
	}
	if serial != root.serial {
		t.Fatalf("probe serial = %d, want %d", serial, root.serial)
	}
}

func TestAXFRRefusesNonZoneStream(t *testing.T) {
	// A stream that does not open with the apex SOA is not a zone.
	notSOA := rrsFromText(t, "com. 172800 IN NS ns.com.")
	addr := axfrServer(t, append(notSOA, rrsFromText(t,
		". 86400 IN SOA a. b. 1 1800 900 604800 86400")...))
	// axfrServer always puts the SOA first, so build the refusal case
	// directly: a server that answers AXFR with a bare NS.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		co := &dnsclient.Conn{Conn: c}
		req, err := co.ReadMsg()
		if err != nil {
			return
		}
		m := new(dns.Msg)
		m.SetReply(req)
		m.Answer = notSOA
		_ = co.WriteMsg(m)
	}()

	if _, err := axfr(context.Background(), l.Addr().String(), 2*time.Second); err == nil {
		t.Fatal("a stream that opened without the apex SOA was accepted")
	}
	_ = addr // the well-formed server above stays for symmetry
}
