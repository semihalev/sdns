package ddr

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// serve runs one question through the middleware, message-born or
// wire-born, and reports the answer and whether the query went on down the
// chain (and, if it did, whether it was still undecoded).
func serve(t *testing.T, d *DDR, qname string, qtype, qclass uint16, wire bool) (resp *dns.Msg, passed, undecoded bool) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(qname, qtype)
	q.Question[0].Qclass = qclass
	q.RecursionDesired = true

	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		undecoded = ch.Request.Undecoded()
		ch.Cancel()
	})
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{d, next})
	if wire {
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("ParseWire refused the query")
		}
		ch.ResetWire(w, req)
	} else {
		ch.Reset(w, q)
	}
	ch.Next(context.Background())
	if w.Written() {
		resp = w.Msg()
	}
	return resp, passed, undecoded
}

func enabled(binds ...string) *config.Config {
	cfg := new(config.Config)
	cfg.DDR.Enabled = true
	cfg.DDR.Name = "DNS.Example.COM"
	cfg.BindDOH, cfg.BindTLS, cfg.BindDOQ = binds[0], binds[1], binds[2]
	return cfg
}

func param[T dns.SVCBKeyValue](rr *dns.SVCB) (T, bool) {
	for _, v := range rr.Value {
		if p, ok := v.(T); ok {
			return p, true
		}
	}
	var zero T
	return zero, false
}

// TestDiscoveryRecords pins what a client is told: one ServiceMode record
// per encrypted listener in preference order, the ALPN each speaks, a port
// only where it is not the transport's default, the DoH template only on
// DoH, and the configured name as the target. The records survive a pack
// and an unpack, which is what the client actually reads.
func TestDiscoveryRecords(t *testing.T) {
	d := New(enabled(":443", ":853", ":8853"))

	for _, wire := range []bool{false, true} {
		resp, passed, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, wire)
		if passed || resp == nil {
			t.Fatalf("wire=%v: discovery query was not answered here", wire)
		}
		raw, err := resp.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if err := resp.Unpack(raw); err != nil {
			t.Fatal(err)
		}
		if resp.Rcode != dns.RcodeSuccess || !resp.Authoritative || len(resp.Answer) != 3 {
			t.Fatalf("wire=%v: rcode %d aa %v answers %d, want NOERROR, AA and three records",
				wire, resp.Rcode, resp.Authoritative, len(resp.Answer))
		}

		want := []struct {
			alpn []string
			port uint16 // 0 means absent
			path bool
		}{
			{[]string{"h2", "h3"}, 0, true},
			{[]string{"dot"}, 0, false},
			{[]string{"doq"}, 8853, false},
		}
		for i, rr := range resp.Answer {
			svcb, ok := rr.(*dns.SVCB)
			if !ok {
				t.Fatalf("answer %d is %T", i, rr)
			}
			if svcb.Priority != uint16(i+1) || svcb.Target != "dns.example.com." || svcb.Hdr.Ttl != ttl { //nolint:gosec // G115 - three records
				t.Fatalf("record %d: priority %d target %q ttl %d", i, svcb.Priority, svcb.Target, svcb.Hdr.Ttl)
			}
			alpn, _ := param[*dns.SVCBAlpn](svcb)
			if alpn == nil || len(alpn.Alpn) != len(want[i].alpn) {
				t.Fatalf("record %d: alpn %v, want %v", i, alpn, want[i].alpn)
			}
			for j := range alpn.Alpn {
				if alpn.Alpn[j] != want[i].alpn[j] {
					t.Fatalf("record %d: alpn %v, want %v", i, alpn.Alpn, want[i].alpn)
				}
			}
			port, hasPort := param[*dns.SVCBPort](svcb)
			if (want[i].port == 0) == hasPort || (hasPort && port.Port != want[i].port) {
				t.Fatalf("record %d: port present %v %v, want %d", i, hasPort, port, want[i].port)
			}
			path, hasPath := param[*dns.SVCBDoHPath](svcb)
			if hasPath != want[i].path || (hasPath && path.Template != dohPath) {
				t.Fatalf("record %d: dohpath %v %v, want %v", i, hasPath, path, want[i].path)
			}
		}
	}
}

// TestOnlyConfiguredListenersAreAdvertised: a server with DoT alone offers
// DoT alone, at priority 1, and a listener bound to one address offers that
// address as a hint while a wildcard bind offers none.
func TestOnlyConfiguredListenersAreAdvertised(t *testing.T) {
	d := New(enabled("", "192.0.2.53:853", "[2001:db8::53]:853"))
	resp, _, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if resp == nil || len(resp.Answer) != 2 {
		t.Fatalf("want two records, got %v", resp)
	}
	dot := resp.Answer[0].(*dns.SVCB)
	if dot.Priority != 1 {
		t.Fatalf("DoT priority %d, want 1 when it is the first listener", dot.Priority)
	}
	if h, ok := param[*dns.SVCBIPv4Hint](dot); !ok || !h.Hint[0].Equal(net.ParseIP("192.0.2.53")) {
		t.Fatalf("DoT hint %v", h)
	}
	if h, ok := param[*dns.SVCBIPv6Hint](resp.Answer[1].(*dns.SVCB)); !ok || !h.Hint[0].Equal(net.ParseIP("2001:db8::53")) {
		t.Fatalf("DoQ hint %v", h)
	}

	wild := New(enabled(":443", "", ""))
	resp, _, _ = serve(t, wild, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if _, ok := param[*dns.SVCBIPv4Hint](resp.Answer[0].(*dns.SVCB)); ok {
		t.Fatal("a wildcard bind offered an address hint")
	}
}

// TestZoneIsAlwaysLocal pins RFC 9462 §6: every name in resolver.arpa is
// answered here and never sent on, with NODATA (not NXDOMAIN) for anything
// but the discovery record, and the same with discovery switched off. The
// owner name echoes the question's spelling.
func TestZoneIsAlwaysLocal(t *testing.T) {
	on := New(enabled(":443", "", ""))
	off := New(new(config.Config))

	for _, tc := range []struct {
		name   string
		d      *DDR
		qname  string
		qtype  uint16
		answer bool
	}{
		{"discovery, mixed case", on, "_DNS.Resolver.ARPA.", dns.TypeSVCB, true},
		{"discovery with DDR off", off, "_dns.resolver.arpa.", dns.TypeSVCB, false},
		{"another type at the discovery name", on, "_dns.resolver.arpa.", dns.TypeA, false},
		{"HTTPS at the discovery name", on, "_dns.resolver.arpa.", dns.TypeHTTPS, false},
		{"the apex", on, "resolver.arpa.", dns.TypeSVCB, false},
		{"another name in the zone", on, "x.resolver.arpa.", dns.TypeA, false},
	} {
		for _, wire := range []bool{false, true} {
			resp, passed, _ := serve(t, tc.d, tc.qname, tc.qtype, dns.ClassINET, wire)
			if passed || resp == nil {
				t.Fatalf("%s wire=%v: left the server", tc.name, wire)
			}
			if resp.Rcode != dns.RcodeSuccess {
				t.Fatalf("%s wire=%v: rcode %s, want NOERROR", tc.name, wire, dns.RcodeToString[resp.Rcode])
			}
			if tc.answer {
				if len(resp.Answer) == 0 || resp.Answer[0].Header().Name != tc.qname {
					t.Fatalf("%s wire=%v: answer %v, owner must echo %s", tc.name, wire, resp.Answer, tc.qname)
				}
				continue
			}
			if len(resp.Answer) != 0 || len(resp.Ns) != 1 {
				t.Fatalf("%s wire=%v: want NODATA with a SOA, got answer %v ns %v", tc.name, wire, resp.Answer, resp.Ns)
			}
			if soa, ok := resp.Ns[0].(*dns.SOA); !ok || soa.Hdr.Name != zone {
				t.Fatalf("%s wire=%v: authority %v, want the zone's SOA", tc.name, wire, resp.Ns[0])
			}
		}
	}
}

// TestOtherNamesPassUndecoded: everything outside the zone goes on down the
// chain, and a wire-born query there is not decoded on the way, including
// names that only look like the zone.
func TestOtherNamesPassUndecoded(t *testing.T) {
	d := New(enabled(":443", ":853", ""))
	for _, qname := range []string{"example.com.", "resolver.arpa.example.", "xresolver.arpa.", "in-addr.arpa."} {
		_, passed, undecoded := serve(t, d, qname, dns.TypeA, dns.ClassINET, true)
		if !passed || !undecoded {
			t.Fatalf("%s: passed %v undecoded %v, want passed undecoded", qname, passed, undecoded)
		}
	}
	// In wire form "xresolver.arpa." ends in "resolver\x04arpa\x00" but its
	// label length byte is 9, not 8, so the suffix compare already refuses
	// it. A CHAOS-class question in the zone is not ours either.
	if _, passed, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassCHAOS, false); !passed {
		t.Fatal("a CHAOS question was answered as resolver.arpa")
	}
}
