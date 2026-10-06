package views_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/edns"
	"github.com/semihalev/sdns/middleware/forwarder"
	"github.com/semihalev/sdns/middleware/resolver"
	"github.com/semihalev/sdns/middleware/views"
)

type loopbackUpstream struct {
	addr     string
	mu       sync.Mutex
	counts   map[string]int
	udp, tcp *dns.Server
	udpConn  net.PacketConn
	tcpConn  net.Listener
}

func startLoopbackUpstream(t *testing.T) *loopbackUpstream {
	t.Helper()
	tcpConn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := tcpConn.Addr().(*net.TCPAddr).Port
	udpConn, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		_ = tcpConn.Close()
		t.Fatal(err)
	}
	u := &loopbackUpstream{addr: tcpConn.Addr().String(), counts: make(map[string]int), tcpConn: tcpConn, udpConn: udpConn}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		if len(req.Question) != 1 {
			return
		}
		q := req.Question[0]
		key := dns.CanonicalName(q.Name) + fmt.Sprintf("/%d/%s", q.Qtype, w.RemoteAddr().Network())
		u.mu.Lock()
		u.counts[key]++
		u.mu.Unlock()
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Authoritative = true
		if q.Name == "tcp-fallback.example." && w.RemoteAddr().Network() == "udp" {
			resp.Truncated = true
			_ = w.WriteMsg(resp)
			return
		}
		switch q.Qtype {
		case dns.TypeA:
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: q.Qclass, Ttl: 60}, A: net.ParseIP("203.0.113.8").To4()}}
		case dns.TypeAAAA:
			resp.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: q.Qclass, Ttl: 60}, AAAA: net.ParseIP("2001:db8::8")}}
		case dns.TypeTXT:
			resp.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: q.Qclass, Ttl: 60}, Txt: []string{"public"}}}
		case dns.TypeHTTPS:
			resp.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: q.Qclass, Ttl: 60}, Priority: 1, Target: "."}}}
		case dns.TypeSVCB:
			resp.Answer = []dns.RR{&dns.SVCB{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: q.Qclass, Ttl: 60}, Priority: 1, Target: "."}}
		default:
			resp.Answer = []dns.RR{&dns.RFC3597{Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: q.Qclass, Ttl: 60}, Rdata: "abcd"}}
		}
		_ = w.WriteMsg(resp)
	})
	started := make(chan struct{}, 2)
	u.udp = &dns.Server{PacketConn: udpConn, Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	u.tcp = &dns.Server{Listener: tcpConn, Handler: handler, NotifyStartedFunc: func() { started <- struct{}{} }}
	serveErr := make(chan error, 2)
	go func() { serveErr <- u.udp.ActivateAndServe() }()
	go func() { serveErr <- u.tcp.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = u.udp.Shutdown()
		_ = u.tcp.Shutdown()
		for i := 0; i < 2; i++ {
			select {
			case err := <-serveErr:
				if err != nil {
					t.Errorf("upstream server: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("upstream server did not stop")
			}
		}
	})
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("loopback upstream did not start both transports")
		}
	}
	return u
}

func (u *loopbackUpstream) count(name string, qtype uint16) int {
	return u.countTransport(name, qtype, "udp") + u.countTransport(name, qtype, "tcp")
}

func (u *loopbackUpstream) countTransport(name string, qtype uint16, transport string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.counts[dns.CanonicalName(name)+fmt.Sprintf("/%d/%s", qtype, transport)]
}

type clientTransport struct{ dns.ResponseWriter }

func (w clientTransport) LocalAddr() net.Addr  { return w.ResponseWriter.LocalAddr() }
func (w clientTransport) RemoteAddr() net.Addr { return w.ResponseWriter.RemoteAddr() }
func (w clientTransport) Close() error         { return nil }

type chainHandler struct {
	handlers []middleware.Handler
	wire     bool
}

func (h chainHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	ch := middleware.NewChain(h.handlers)
	if h.wire {
		raw, err := req.Pack()
		if err != nil {
			panic(err)
		}
		wireReq := new(middleware.Request)
		if !wireReq.ParseWire(raw, time.Now(), nil) {
			panic("fixture query did not qualify for wire path")
		}
		ch.ResetWire(clientTransport{w}, wireReq)
	} else {
		ch.Reset(clientTransport{w}, req)
	}
	ch.Next(context.Background())
	ch.Finish()
}

func configFor(upstream string, mode string) *config.Config {
	return &config.Config{
		Directory: "/tmp", DNSSEC: "off", Timeout: config.Duration{Duration: time.Second}, QueryTimeout: config.Duration{Duration: 2 * time.Second},
		CacheSize: 1024, Expire: 600, ForwarderServers: []string{upstream},
		Views: []config.ViewConfig{{Mode: mode, Zone: "test", Networks: []string{"127.0.0.0/8"}, Answers: []string{
			"service.example. 60 IN A 192.0.2.10",
			"alias.example. 60 IN CNAME target.public.",
			"*.local.example. 60 IN A 192.0.2.20",
		}}},
	}
}

func startClientServerMode(t *testing.T, handlers []middleware.Handler, wire bool) (string, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := pc.LocalAddr().String()
	tcpListener, err := net.Listen("tcp", addr)
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
	}
	started := make(chan struct{}, 2)
	udpServer := &dns.Server{PacketConn: pc, Handler: chainHandler{handlers, wire}, NotifyStartedFunc: func() { started <- struct{}{} }}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: chainHandler{handlers, wire}, NotifyStartedFunc: func() { started <- struct{}{} }}
	errch := make(chan error, 2)
	go func() { errch <- udpServer.ActivateAndServe() }()
	go func() { errch <- tcpServer.ActivateAndServe() }()
	cleanup := func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
		for i := 0; i < 2; i++ {
			select {
			case err := <-errch:
				if err != nil {
					t.Errorf("client server: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Error("client server did not stop")
			}
		}
	}
	t.Cleanup(cleanup)
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(2 * time.Second):
			t.Fatal("client server did not start both transports")
		}
	}
	return addr, cleanup
}

func startClientServer(t *testing.T, handlers []middleware.Handler) (string, func()) {
	return startClientServerMode(t, handlers, false)
}

func query(t *testing.T, addr, transport, name string, qtype uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	resp, _, err := (&dns.Client{Net: transport, Timeout: 2 * time.Second}).Exchange(req, addr)
	if err != nil {
		t.Fatalf("%s query %s/%d: %v", transport, name, qtype, err)
	}
	return resp
}

func TestOwnerAuthoritativeRealClientAndUpstreamTransports(t *testing.T) {
	up := startLoopbackUpstream(t)
	for _, tc := range []struct {
		name, mode string
		owned      bool
	}{{"default", "", false}, {"overlay", "overlay", false}, {"authoritative-owner", "authoritative-owner", true}} {
		t.Run(tc.name, func(t *testing.T) {
			baselineAAAA := up.count("service.example.", dns.TypeAAAA)
			cfg := configFor(up.addr, tc.mode)
			handlers := []middleware.Handler{edns.New(cfg), views.New(cfg), forwarder.New(cfg)}
			addr, _ := startClientServer(t, handlers)
			for _, proto := range []string{"udp", "tcp"} {
				resp := query(t, addr, proto, "service.example.", dns.TypeA)
				if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
					t.Fatalf("%s local A response = rcode %d, answers %v", proto, resp.Rcode, resp.Answer)
				}
				if got := resp.Answer[0].String(); got != "service.example.\t60\tIN\tA\t192.0.2.10" {
					t.Errorf("local A = %q", got)
				}
				if tc.owned {
					for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeTXT, 65280} {
						before := up.count("service.example.", qt)
						resp = query(t, addr, proto, "service.example.", qt)
						if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
							t.Errorf("owned missing type %d: rcode=%d answers=%v authority=%v", qt, resp.Rcode, resp.Answer, resp.Ns)
						}
						if got := up.count("service.example.", qt); got != before {
							t.Errorf("owned missing type %d reached upstream %d times", qt, got-before)
						}
					}
					beforeAlias := up.count("alias.example.", dns.TypeA)
					beforeTarget := up.count("target.public.", dns.TypeA)
					cname := query(t, addr, proto, "alias.example.", dns.TypeA)
					if cname.Rcode != dns.RcodeSuccess || len(cname.Answer) != 1 || cname.Answer[0].Header().Rrtype != dns.TypeCNAME {
						t.Errorf("owned CNAME response: rcode=%d answer=%v", cname.Rcode, cname.Answer)
					} else if rr, ok := cname.Answer[0].(*dns.CNAME); !ok || dns.CanonicalName(rr.Target) != "target.public." {
						t.Errorf("owned CNAME target = %v, want target.public.", cname.Answer[0])
					}
					if got := up.count("alias.example.", dns.TypeA); got != beforeAlias {
						t.Errorf("owned CNAME query reached upstream %d times", got-beforeAlias)
					}
					if got := up.count("target.public.", dns.TypeA); got != beforeTarget {
						t.Errorf("owned CNAME target was chased upstream %d times", got-beforeTarget)
					}
					beforeWildcard := up.count("host.local.example.", dns.TypeAAAA)
					wild := query(t, addr, proto, "host.local.example.", dns.TypeAAAA)
					if wild.Rcode != dns.RcodeSuccess || len(wild.Answer) != 0 || len(wild.Ns) != 0 {
						t.Errorf("wildcard owner missing type: rcode=%d answers=%v authority=%v", wild.Rcode, wild.Answer, wild.Ns)
					}
					if got := up.count("host.local.example.", dns.TypeAAAA); got != beforeWildcard {
						t.Errorf("wildcard owner miss reached upstream %d times", got-beforeWildcard)
					}
				} else {
					for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB, dns.TypeTXT, 65280} {
						resp = query(t, addr, proto, "service.example.", qt)
						if len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != qt {
							t.Errorf("overlay missing type %d did not fall through: %v", qt, resp.Answer)
						}
					}
				}
				outside := query(t, addr, proto, "outside.example.", dns.TypeA)
				if len(outside.Answer) != 1 || outside.Answer[0].Header().Rrtype != dns.TypeA {
					t.Errorf("out-of-view response: %v", outside.Answer)
				}
				// Each query must exercise the fallback itself; an earlier
				// subtest's cumulative count cannot establish that it did.
				beforeUDP := up.countTransport("tcp-fallback.example.", dns.TypeA, "udp")
				beforeTCP := up.countTransport("tcp-fallback.example.", dns.TypeA, "tcp")
				fallback := query(t, addr, proto, "tcp-fallback.example.", dns.TypeA)
				if fallback.Rcode != dns.RcodeSuccess || len(fallback.Answer) != 1 || fallback.Answer[0].Header().Rrtype != dns.TypeA {
					t.Errorf("TCP fallback response: %v", fallback.Answer)
				} else if a, ok := fallback.Answer[0].(*dns.A); !ok || a.A.String() != "203.0.113.8" {
					t.Errorf("TCP fallback address = %v, want upstream 203.0.113.8", fallback.Answer[0])
				}
				if got := up.countTransport("tcp-fallback.example.", dns.TypeA, "udp") - beforeUDP; got != 1 {
					t.Errorf("fallback UDP requests = %d, want 1", got)
				}
				if got := up.countTransport("tcp-fallback.example.", dns.TypeA, "tcp") - beforeTCP; got != 1 {
					t.Errorf("fallback TCP requests = %d, want 1", got)
				}
			}
			if tc.owned && up.count("service.example.", dns.TypeAAAA) != baselineAAAA {
				t.Errorf("authoritative missing AAAA reached upstream %d times", up.count("service.example.", dns.TypeAAAA)-baselineAAAA)
			}
		})
	}
}

func TestOwnerAuthoritativeGoResolver(t *testing.T) {
	up := startLoopbackUpstream(t)
	cfg := configFor(up.addr, "authoritative-owner")
	// A local target does not complete an alias's answer: the view returns
	// only its CNAME, even though it could answer a separate target query.
	cfg.Views[0].Answers = append(cfg.Views[0].Answers, "target.public. 60 IN A 192.0.2.30")
	addr, _ := startClientServer(t, []middleware.Handler{edns.New(cfg), views.New(cfg), forwarder.New(cfg)})
	dialer := &net.Dialer{}
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, addr)
		},
	}
	for _, tc := range []struct {
		name, network, host, wantIP string
		qtype                       uint16
	}{
		{"direct IPv4", "ip4", "service.example.", "192.0.2.10", dns.TypeA},
		{"owned missing IPv6", "ip6", "service.example.", "", dns.TypeAAAA},
		{"CNAME-only IPv4", "ip4", "alias.example.", "", dns.TypeA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := up.count(tc.host, tc.qtype)
			beforeTarget := up.count("target.public.", dns.TypeA)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			ips, err := r.LookupIP(ctx, tc.network, tc.host)
			if tc.wantIP != "" {
				if err != nil || len(ips) != 1 || ips[0].String() != tc.wantIP {
					t.Errorf("LookupIP = (%v, %v), want %s", ips, err, tc.wantIP)
				}
			} else {
				// Go expects the requested address RRset in a recursive reply;
				// this characterizes the CNAME-only policy's client limitation.
				var dnsErr *net.DNSError
				if len(ips) != 0 || !errors.As(err, &dnsErr) || !dnsErr.IsNotFound {
					t.Errorf("LookupIP = (%v, %v), want no addresses and DNS not-found", ips, err)
				}
			}
			if got := up.count(tc.host, tc.qtype) - before; got != 0 {
				t.Errorf("owned lookup made %d upstream requests", got)
			}
			if got := up.count("target.public.", dns.TypeA) - beforeTarget; got != 0 {
				t.Errorf("CNAME target made %d upstream requests", got)
			}
		})
	}
}

func TestOwnerAuthoritativeEDNSFlagsDecodedAndWire(t *testing.T) {
	for _, wireBorn := range []bool{false, true} {
		t.Run(map[bool]string{false: "decoded", true: "wire"}[wireBorn], func(t *testing.T) {
			cfg := configFor("127.0.0.1:9", "authoritative-owner")
			addr, _ := startClientServerMode(t, []middleware.Handler{edns.New(cfg), views.New(cfg)}, wireBorn)
			for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
				for _, tc := range []struct{ do, rd, cd bool }{
					{false, false, false}, {false, true, true}, {true, false, true}, {true, true, false},
				} {
					req := new(dns.Msg)
					req.SetQuestion("service.example.", qtype)
					req.RecursionDesired, req.CheckingDisabled, req.AuthenticatedData = tc.rd, tc.cd, true
					req.SetEdns0(1232, tc.do)
					resp, _, err := (&dns.Client{Net: "udp", Timeout: 2 * time.Second}).Exchange(req, addr)
					if err != nil {
						t.Fatalf("wire=%v DO=%v RD=%v CD=%v: %v", wireBorn, tc.do, tc.rd, tc.cd, err)
					}
					if !resp.Authoritative || !resp.RecursionAvailable || resp.AuthenticatedData || resp.RecursionDesired != tc.rd || resp.CheckingDisabled != tc.cd {
						t.Errorf("wire=%v qtype=%d DO=%v RD=%v CD=%v flags: AA=%v RA=%v AD=%v RD=%v CD=%v", wireBorn, qtype, tc.do, tc.rd, tc.cd, resp.Authoritative, resp.RecursionAvailable, resp.AuthenticatedData, resp.RecursionDesired, resp.CheckingDisabled)
					}
					switch {
					case resp.Rcode != dns.RcodeSuccess:
						t.Errorf("wire=%v qtype=%d response rcode=%d", wireBorn, qtype, resp.Rcode)
					case qtype == dns.TypeA && len(resp.Answer) != 1:
						t.Errorf("wire=%v positive A answers=%v", wireBorn, resp.Answer)
					case qtype == dns.TypeAAAA && (len(resp.Answer) != 0 || len(resp.Ns) != 0):
						t.Errorf("wire=%v NODATA answer=%v authority=%v", wireBorn, resp.Answer, resp.Ns)
					}
					opt := resp.IsEdns0()
					if opt == nil || opt.Do() != tc.do {
						t.Errorf("wire=%v DO=%v response OPT=%v", wireBorn, tc.do, opt)
					}
				}
			}
		})
	}
}

func serveChain(t *testing.T, handlers []middleware.Handler, client, name string, qtype, qclass uint16) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(name), qtype)
	req.Question[0].Qclass = qclass
	req.SetEdns0(1232, false)
	w := mock.NewWriter("udp", client)
	ch := middleware.NewChain(handlers)
	ch.Reset(w, req)
	ch.Next(context.Background())
	ch.Finish()
	if !w.Written() {
		t.Fatalf("query %s/%d/%d from %s was not answered", name, qtype, qclass, client)
	}
	return w.Msg()
}

func TestOwnerAuthoritativeSharedAnswerCacheIsolation(t *testing.T) {
	up := startLoopbackUpstream(t)
	cfg := configFor(up.addr, "authoritative-owner")
	c := cache.New(cfg)
	t.Cleanup(c.Stop)
	f := forwarder.New(cfg)
	ed := edns.New(cfg)
	v := views.New(cfg)
	// Prime a public AAAA answer while the client is outside the view.
	outside := []middleware.Handler{ed, c, f}
	primed := serveChain(t, outside, "8.8.8.8:1234", "service.example.", dns.TypeAAAA, dns.ClassINET)
	if len(primed.Answer) != 1 || primed.Answer[0].Header().Rrtype != dns.TypeAAAA {
		t.Fatalf("public cache prime: %v", primed.Answer)
	}
	before := up.count("service.example.", dns.TypeAAAA)
	inside := []middleware.Handler{ed, v, c, f}
	local := serveChain(t, inside, "127.0.0.1:1234", "service.example.", dns.TypeAAAA, dns.ClassINET)
	if len(local.Answer) != 0 || local.Rcode != dns.RcodeSuccess || !local.Authoritative {
		t.Fatalf("owned NODATA = rcode %d answer %v AA %v", local.Rcode, local.Answer, local.Authoritative)
	}
	if got := up.count("service.example.", dns.TypeAAAA); got != before {
		t.Errorf("owned NODATA made %d upstream calls", got-before)
	}
	stillCached := serveChain(t, outside, "8.8.8.8:1235", "service.example.", dns.TypeAAAA, dns.ClassINET)
	if len(stillCached.Answer) != 1 || stillCached.Answer[0].Header().Rrtype != dns.TypeAAAA {
		t.Fatalf("out-of-view cached answer lost: %v", stillCached.Answer)
	}
	if got := up.count("service.example.", dns.TypeAAAA); got != before {
		t.Errorf("out-of-view cache hit made %d new upstream calls", got-before)
	}
}

func TestOwnerAuthoritativeDeclinedQuestionsReachResolverPolicy(t *testing.T) {
	up := startLoopbackUpstream(t)
	cfg := configFor(up.addr, "authoritative-owner")
	cfg.Directory = t.TempDir()
	cfg.RootServers = []string{up.addr}
	h := resolver.New(cfg)
	t.Cleanup(h.Stop)
	handlers := []middleware.Handler{edns.New(cfg), views.New(cfg), h, forwarder.New(cfg)}
	for _, tc := range []struct {
		name       string
		typ, class uint16
		rcode      uint8
		ede        uint16
	}{
		{"ANY", dns.TypeANY, dns.ClassINET, dns.RcodeNotImplemented, dns.ExtendedErrorCodeNotSupported},
		{"AXFR", dns.TypeAXFR, dns.ClassINET, dns.RcodeRefused, 0},
		{"IXFR", dns.TypeIXFR, dns.ClassINET, dns.RcodeRefused, 0},
		{"NXNAME", dns.TypeNXNAME, dns.ClassINET, dns.RcodeFormatError, dns.ExtendedErrorCodeInvalidQueryType},
		{"CH", dns.TypeA, dns.ClassCHAOS, dns.RcodeRefused, 0},
		{"other-class", dns.TypeA, dns.ClassHESIOD, dns.RcodeNotImplemented, dns.ExtendedErrorCodeNotSupported},
	} {
		before := up.count("service.example.", tc.typ)
		resp := serveChain(t, handlers, "127.0.0.1:2345", "service.example.", tc.typ, tc.class)
		if resp.Rcode != int(tc.rcode) {
			t.Errorf("%s rcode=%d want %d", tc.name, resp.Rcode, tc.rcode)
		}
		var gotEDE uint16
		if opt := resp.IsEdns0(); opt != nil {
			for _, o := range opt.Option {
				if ede, ok := o.(*dns.EDNS0_EDE); ok {
					gotEDE = ede.InfoCode
				}
			}
		}
		if gotEDE != tc.ede {
			t.Errorf("%s EDE=%d want %d", tc.name, gotEDE, tc.ede)
		}
		if up.count("service.example.", tc.typ) != before {
			t.Errorf("%s reached upstream", tc.name)
		}
	}
}

func TestOwnerAuthoritativeEscapedNamesOverTransports(t *testing.T) {
	up := startLoopbackUpstream(t)
	cfg := configFor(up.addr, "authoritative-owner")
	cfg.Views[0].Answers = []string{
		`\097lias.example. 60 IN A 192.0.2.10`,
		`Alias.Example. 60 IN A 192.0.2.11`,
		`\111nly.example. 60 IN A 192.0.2.12`,
		`*.example.lan. 60 IN A 192.0.2.20`,
	}
	addr, _ := startClientServer(t, []middleware.Handler{edns.New(cfg), views.New(cfg), forwarder.New(cfg)})
	for _, proto := range []string{"udp", "tcp"} {
		t.Run(proto, func(t *testing.T) {
			// Packing the question gives the server a wire name, while the
			// configured RRset retains both presentation spellings of alias.
			const alias = "ALIAS.Example."
			before := up.count(alias, dns.TypeA)
			resp := query(t, addr, proto, alias, dns.TypeA)
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 2 || len(resp.Ns) != 0 {
				t.Errorf("escaped owner RRset: rcode=%d answer=%v authority=%v", resp.Rcode, resp.Answer, resp.Ns)
			} else {
				for i, want := range []string{"192.0.2.10", "192.0.2.11"} {
					a, ok := resp.Answer[i].(*dns.A)
					if !ok || a.Hdr.Name != alias || a.Hdr.Class != dns.ClassINET || a.A.String() != want {
						t.Errorf("escaped owner answer %d = %v, want %s IN A %s", i, resp.Answer[i], alias, want)
					}
				}
			}
			if got := up.count(alias, dns.TypeA); got != before {
				t.Errorf("escaped owner A reached upstream %d times", got-before)
			}

			const only = "only.example."
			before = up.count(only, dns.TypeAAAA)
			resp = query(t, addr, proto, only, dns.TypeAAAA)
			if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
				t.Errorf("escaped owner missing type: rcode=%d answer=%v authority=%v", resp.Rcode, resp.Answer, resp.Ns)
			}
			if got := up.count(only, dns.TypeAAAA); got != before {
				t.Errorf("escaped owner missing AAAA reached upstream %d times", got-before)
			}

			// The first label is "foo.example", so this name is outside
			// example.lan. despite its apparent presentation-string suffix.
			const outside = `foo\.example.lan.`
			for _, tc := range []struct {
				qtype uint16
				want  string
			}{{dns.TypeA, "203.0.113.8"}, {dns.TypeAAAA, "2001:db8::8"}} {
				before = up.count(outside, tc.qtype)
				resp = query(t, addr, proto, outside, tc.qtype)
				if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != tc.qtype {
					t.Errorf("escaped-dot fallthrough type %d: rcode=%d answer=%v", tc.qtype, resp.Rcode, resp.Answer)
				} else {
					var got string
					switch rr := resp.Answer[0].(type) {
					case *dns.A:
						got = rr.A.String()
					case *dns.AAAA:
						got = rr.AAAA.String()
					}
					if got != tc.want {
						t.Errorf("escaped-dot type %d address=%s, want upstream %s", tc.qtype, got, tc.want)
					}
				}
				if got := up.count(outside, tc.qtype); got != before+1 {
					t.Errorf("escaped-dot type %d upstream calls=%d, want 1", tc.qtype, got-before)
				}
			}
		})
	}
}
