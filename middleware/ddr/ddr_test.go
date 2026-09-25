package ddr

import (
	"context"
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
// DoT alone, at priority 1. No record carries an address hint, a listener
// bound to one address included: behind a load balancer, NAT or a proxy that
// address is not the one clients reach, and they resolve the target instead.
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
	for _, rr := range resp.Answer {
		svcb := rr.(*dns.SVCB)
		if h, ok := param[*dns.SVCBIPv4Hint](svcb); ok {
			t.Fatalf("%v carries the bound address %v as a hint", svcb, h.Hint)
		}
		if h, ok := param[*dns.SVCBIPv6Hint](svcb); ok {
			t.Fatalf("%v carries the bound address %v as a hint", svcb, h.Hint)
		}
	}
}

// Configured hints, and only they, are carried, in every record: the bound
// address never stands in for them.
func TestConfiguredHintsAreCarried(t *testing.T) {
	cfg := enabled("192.0.2.53:443", "192.0.2.53:853", "")
	cfg.DDR.IPv4Hint = []string{"198.51.100.1", "198.51.100.2"}
	cfg.DDR.IPv6Hint = []string{"2001:db8::1"}
	rrs := advertised(t, New(cfg))
	if len(rrs) != 2 {
		t.Fatalf("records %v, want DoH and DoT", rrs)
	}
	for _, rr := range rrs {
		v4, ok4 := param[*dns.SVCBIPv4Hint](rr)
		v6, ok6 := param[*dns.SVCBIPv6Hint](rr)
		if !ok4 || len(v4.Hint) != 2 || v4.Hint[0].String() != "198.51.100.1" || v4.Hint[1].String() != "198.51.100.2" {
			t.Fatalf("%v: ipv4hint %v, want the configured two", rr, v4)
		}
		if !ok6 || len(v6.Hint) != 1 || v6.Hint[0].String() != "2001:db8::1" {
			t.Fatalf("%v: ipv6hint %v, want the configured one", rr, v6)
		}
	}

	// A value the config gate refuses, reached by a caller that skipped it,
	// carries no hint rather than a wrong one.
	cfg.DDR.IPv4Hint = []string{"127.0.0.1"}
	for _, rr := range advertised(t, New(cfg)) {
		if _, ok := param[*dns.SVCBIPv4Hint](rr); ok {
			t.Fatalf("%v carries a refused hint", rr)
		}
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

// TestServiceNamePorts: a listener written with a service name, which the
// config gate and the listener both accept, is advertised with the port the
// name resolves to. It used to be dropped, so a server whose only encrypted
// listener was ":https" answered discovery with NODATA.
func TestServiceNamePorts(t *testing.T) {
	d := New(enabled(":https", "", ":domain"))
	resp, _, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if resp == nil || len(resp.Answer) != 2 {
		t.Fatalf("want the DoH and DoQ records, got %v", resp)
	}
	if _, ok := param[*dns.SVCBPort](resp.Answer[0].(*dns.SVCB)); ok {
		t.Fatal(":https resolves to DoH's default port and must carry no port")
	}
	if p, ok := param[*dns.SVCBPort](resp.Answer[1].(*dns.SVCB)); !ok || p.Port != 53 {
		t.Fatalf(":domain on DoQ must carry port 53, got %v", p)
	}
}

// TestOnlyListenersThatAreUpAreAdvertised: once the server reports which
// listeners are up, a listener that failed is left out and the priorities
// close up, DoH offers only the HTTP versions it serves, and with nothing up
// the discovery answer is NODATA.
func TestOnlyListenersThatAreUpAreAdvertised(t *testing.T) {
	d := New(enabled(":443", ":853", ":8853"))
	up := map[string]bool{"doh": true, "doh3": false, "tls": false, "doq": true}
	d.ObserveListeners(func(proto string) bool { return up[proto] })

	resp, _, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if resp == nil || len(resp.Answer) != 2 {
		t.Fatalf("want DoH and DoQ, got %v", resp)
	}
	doh, doq := resp.Answer[0].(*dns.SVCB), resp.Answer[1].(*dns.SVCB)
	if a, _ := param[*dns.SVCBAlpn](doh); doh.Priority != 1 || len(a.Alpn) != 1 || a.Alpn[0] != "h2" {
		t.Fatalf("DoH record %v, want priority 1 offering h2 alone", doh)
	}
	if a, _ := param[*dns.SVCBAlpn](doq); doq.Priority != 2 || a.Alpn[0] != "doq" {
		t.Fatalf("DoQ record %v, want priority 2 once DoT is left out", doq)
	}

	// The state is read per query.
	up["tls"] = true
	resp, _, _ = serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if len(resp.Answer) != 3 {
		t.Fatalf("DoT came up and was not advertised: %v", resp.Answer)
	}

	for k := range up {
		up[k] = false
	}
	resp, _, _ = serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 1 {
		t.Fatalf("with nothing up, want NODATA, got %v", resp)
	}
}

// advertised asks for the discovery records and returns them.
func advertised(t *testing.T, d *DDR) []*dns.SVCB {
	t.Helper()
	resp, _, _ := serve(t, d, "_dns.resolver.arpa.", dns.TypeSVCB, dns.ClassINET, false)
	if resp == nil {
		t.Fatal("discovery query was not answered")
	}
	out := make([]*dns.SVCB, 0, len(resp.Answer))
	for _, rr := range resp.Answer {
		out = append(out, rr.(*dns.SVCB))
	}
	return out
}

// A listener bound to loopback is one no client can reach: it is neither
// advertised nor offered as a hint. A DoH listener behind a reverse proxy is
// advertised as the proxy publishes it once ddr.doh_port says so.
func TestLoopbackListenersAndProxiedDoH(t *testing.T) {
	alpnOf := func(rr *dns.SVCB) []string {
		a, _ := param[*dns.SVCBAlpn](rr)
		if a == nil {
			return nil
		}
		return a.Alpn
	}
	noHint := func(t *testing.T, rr *dns.SVCB) {
		t.Helper()
		if h, ok := param[*dns.SVCBIPv4Hint](rr); ok {
			t.Fatalf("%v advertises the hint %v", alpnOf(rr), h.Hint)
		}
		if h, ok := param[*dns.SVCBIPv6Hint](rr); ok {
			t.Fatalf("%v advertises the hint %v", alpnOf(rr), h.Hint)
		}
	}

	t.Run("loopback listeners are left out", func(t *testing.T) {
		for _, doh := range []string{
			"127.0.0.1:8053", "[::1]:8053", "[::ffff:127.0.0.1]:8053",
			"localhost:8053", "localhost.:8053", "LOCALHOST.:8053", "ns.localhost:8053",
		} {
			rrs := advertised(t, New(enabled(doh, ":853", ":853")))
			if len(rrs) != 2 || alpnOf(rrs[0])[0] != "dot" || alpnOf(rrs[1])[0] != "doq" {
				t.Fatalf("DoH on %s: records %v, want DoT and DoQ only", doh, rrs)
			}
			for _, rr := range rrs {
				noHint(t, rr)
			}
		}
		if rrs := advertised(t, New(enabled("", "127.0.0.1:853", ""))); len(rrs) != 0 {
			t.Fatalf("DoT on loopback advertised: %v", rrs)
		}
	})

	t.Run("proxied DoH on the default port", func(t *testing.T) {
		cfg := enabled("127.0.0.1:8053", ":853", "")
		cfg.DDR.DoHPort, cfg.DDR.DoHALPN = 443, []string{"h2"}
		rrs := advertised(t, New(cfg))
		if len(rrs) != 2 || rrs[0].Priority != 1 {
			t.Fatalf("records %v, want DoH first, then DoT", rrs)
		}
		doh := rrs[0]
		if a := alpnOf(doh); len(a) != 1 || a[0] != "h2" {
			t.Fatalf("DoH alpn %v, want the proxy's h2", a)
		}
		if p, ok := param[*dns.SVCBPort](doh); ok {
			t.Fatalf("DoH carries port %d for the default 443", p.Port)
		}
		if _, ok := param[*dns.SVCBDoHPath](doh); !ok {
			t.Fatal("DoH lost its URI template")
		}
		noHint(t, doh)
	})

	t.Run("proxied DoH on another port", func(t *testing.T) {
		cfg := enabled("192.0.2.53:8053", "", "")
		cfg.DDR.DoHPort = 8443
		rrs := advertised(t, New(cfg))
		if len(rrs) != 1 {
			t.Fatalf("records %v, want DoH alone", rrs)
		}
		if p, ok := param[*dns.SVCBPort](rrs[0]); !ok || p.Port != 8443 {
			t.Fatalf("DoH port %v, want the proxy's 8443", p)
		}
		// The listener's own address is not where the proxy is.
		noHint(t, rrs[0])
		if a := alpnOf(rrs[0]); len(a) != 2 || a[0] != "h2" || a[1] != "h3" {
			t.Fatalf("DoH alpn %v, want the listener's own h2 and h3", a)
		}
	})

	t.Run("proxy ALPNs follow the listener's TCP side", func(t *testing.T) {
		cfg := enabled("127.0.0.1:8053", "", "")
		cfg.DDR.DoHPort, cfg.DDR.DoHALPN = 443, []string{"h2", "h3"}
		d := New(cfg)
		d.ObserveListeners(func(proto string) bool { return proto == "doh" })
		if rrs := advertised(t, d); len(rrs) != 1 || len(alpnOf(rrs[0])) != 2 {
			t.Fatalf("records %v, want DoH with both proxy ALPNs", rrs)
		}
		d.ObserveListeners(func(string) bool { return false })
		if rrs := advertised(t, d); len(rrs) != 0 {
			t.Fatalf("records %v, want none while the DoH listener is down", rrs)
		}
	})

	// With the port alone the listener's own ALPNs stand for the proxy's,
	// and they too follow the TCP side the proxy reaches: local QUIC being
	// up says nothing about a proxy whose backend is down.
	t.Run("inherited ALPNs follow the listener's TCP side", func(t *testing.T) {
		cfg := enabled("127.0.0.1:8053", "", "")
		cfg.DDR.DoHPort = 443
		d := New(cfg)
		d.ObserveListeners(func(proto string) bool { return proto == "doh3" })
		if rrs := advertised(t, d); len(rrs) != 0 {
			t.Fatalf("records %v, want none while the TCP DoH listener is down", rrs)
		}
		d.ObserveListeners(func(proto string) bool { return proto == "doh" })
		if rrs := advertised(t, d); len(rrs) != 1 || len(alpnOf(rrs[0])) != 2 {
			t.Fatalf("records %v, want DoH with the listener's h2 and h3", rrs)
		}
	})
}
