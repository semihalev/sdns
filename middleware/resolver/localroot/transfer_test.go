package localroot

import (
	"context"
	"errors"
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
	if _, err := verifyZone(got, root.anchors); err != nil {
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

func TestAXFRRefusesMismatchedClosingSOA(t *testing.T) {
	root := buildTestRoot(t)

	var opening dns.RR
	body := make([]dns.RR, 0, len(root.rrs))
	for _, rr := range root.rrs {
		if rr.Header().Rrtype == dns.TypeSOA && dns.CanonicalName(rr.Header().Name) == "." {
			opening = rr
			continue
		}
		body = append(body, rr)
	}
	if opening == nil {
		t.Fatal("test zone has no apex SOA")
	}
	// RFC 5936 §2.2: the stream must end with the SOA it began with. This
	// one announces a different zone version at the close, so the records in
	// between belong to no single version of it.
	closing := dns.Copy(opening).(*dns.SOA)
	closing.Serial++

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
		reply := func(rrs []dns.RR) {
			m := new(dns.Msg)
			m.SetReply(req)
			m.Answer = rrs
			_ = co.WriteMsg(m)
		}
		reply(append([]dns.RR{opening}, body...))
		reply([]dns.RR{closing})
	}()

	_, err = axfr(context.Background(), l.Addr().String(), 2*time.Second)
	if !errors.Is(err, errTransferShape) {
		t.Fatalf("mismatched closing SOA: err = %v, want errTransferShape", err)
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

// TestNormalizeZoneKeepsTheLowestTTL pins RFC 2181 §5.2 for the duplicates
// normalization collapses: a receiver holding one RRset's records with
// differing TTLs treats them as if all carried the lowest. Without it the
// surviving record's lifetime would depend on which copy the source happened
// to send first.
func TestNormalizeZoneKeepsTheLowestTTL(t *testing.T) {
	long := rrsFromText(t, "com. 86400 IN NS ns.com.")[0]
	short := dns.Copy(long)
	short.Header().Ttl = 300

	for name, sent := range map[string][]dns.RR{
		"longest first":  {long, short},
		"shortest first": {short, long},
	} {
		t.Run(name, func(t *testing.T) {
			out := normalizeZone(sent)
			if len(out) != 1 {
				t.Fatalf("normalized to %d records, want the duplicate collapsed", len(out))
			}
			if got := out[0].Header().Ttl; got != 300 {
				t.Fatalf("surviving TTL = %d, want the lowest of the two (300)", got)
			}
		})
	}

	// Normalization rewrites TTLs, so it must not do so on the records the
	// caller still holds.
	if long.Header().Ttl != 86400 || short.Header().Ttl != 300 {
		t.Fatalf("normalization mutated its input: %d / %d", long.Header().Ttl, short.Header().Ttl)
	}
}
