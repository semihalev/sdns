package rpz

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsclient"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
)

// feedServer is a loopback AXFR primary whose zone content and serial the
// test rewrites between cycles.
type feedServer struct {
	t      *testing.T
	addr   string
	serial atomic.Uint32
	// rules is the body served; swapped whole.
	rules atomic.Pointer[[]dns.RR]
	// transfers counts AXFR requests served, so a test can assert a
	// cycle never got that far.
	transfers atomic.Int32
	// tsigSecret, when set, verifies the transfer request's TSIG and
	// signs the response envelope.
	tsigName, tsigSecret string
}

func (s *feedServer) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "feed.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns.feed.test.",
		Mbox:    "admin.feed.test.",
		Serial:  s.serial.Load(),
		Refresh: 3600, Retry: 900, Expire: 86400, Minttl: 300,
	}
}

func startFeedServer(t *testing.T, tsigName, tsigSecret string) *feedServer {
	t.Helper()
	s := &feedServer{t: t, tsigName: tsigName, tsigSecret: tsigSecret}
	s.serial.Store(1)
	s.setRules("blocked.example.com.feed.test. 300 IN CNAME .")

	if tsigSecret != "" {
		startTSIGFeedServer(t, s)
		return s
	}

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s.addr = l.Addr().String()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go s.serveConn(c)
		}
	}()
	return s
}

// setRules replaces the served body with records parsed from zone-file
// lines.
func (s *feedServer) setRules(lines ...string) {
	var rrs []dns.RR
	for _, line := range lines {
		rr, err := dns.NewRR(line)
		if err != nil {
			s.t.Fatalf("bad fixture rule %q: %v", line, err)
		}
		rrs = append(rrs, rr)
	}
	s.rules.Store(&rrs)
}

func (s *feedServer) serveConn(c net.Conn) {
	defer func() { _ = c.Close() }()

	co := &dnsclient.Conn{Conn: c}
	req, err := co.ReadMsg()
	if err != nil {
		return
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	switch req.Question[0].Qtype {
	case dns.TypeSOA:
		resp.Answer = []dns.RR{s.soa()}
	case dns.TypeAXFR:
		s.transfers.Add(1)
		body := *s.rules.Load()
		resp.Answer = append([]dns.RR{s.soa()}, body...)
		resp.Answer = append(resp.Answer, s.soa())
	}
	_ = co.WriteMsg(resp)
}

// startTSIGFeedServer runs the signed primary through the library's own
// server and Transfer.Out — the pairing that owns the response-side
// envelope-MAC chain — so our client is verified against what a real
// provider effectively runs, not against a hand-rolled signer. A raw
// dns.Conn cannot stand in here: it never records the request MAC, so
// its response MACs verify against nothing.
func startTSIGFeedServer(t *testing.T, srv *feedServer) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv.addr = l.Addr().String()

	mux := dns.NewServeMux()
	mux.HandleFunc("feed.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		switch req.Question[0].Qtype {
		case dns.TypeSOA:
			resp := new(dns.Msg)
			resp.SetReply(req)
			resp.Answer = []dns.RR{srv.soa()}
			_ = w.WriteMsg(resp)
		case dns.TypeAXFR:
			// The signature is what admits a transfer: absent or bad
			// TSIG is refused — the property the unsigned-client test
			// relies on.
			if req.IsTsig() == nil || w.TsigStatus() != nil {
				resp := new(dns.Msg)
				resp.SetRcode(req, dns.RcodeRefused)
				_ = w.WriteMsg(resp)
				return
			}
			tr := new(dns.Transfer)
			ch := make(chan *dns.Envelope, 1)
			body := *srv.rules.Load()
			rrs := append([]dns.RR{srv.soa()}, body...)
			rrs = append(rrs, srv.soa())
			ch <- &dns.Envelope{RR: rrs}
			close(ch)
			_ = tr.Out(w, req, ch)
		}
	})
	server := &dns.Server{
		Listener:   l,
		Handler:    mux,
		TsigSecret: map[string]string{srv.tsigName: srv.tsigSecret},
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
}

// feedUnderTest builds an RPZ with one AXFR zone and a hand-driven feed —
// the schedule goroutine stays parked so the test drives cycles itself.
func feedUnderTest(t *testing.T, srv *feedServer, tsig string) (*RPZ, *axfrFeed) {
	t.Helper()
	zc := config.RPZZone{Name: "feed", Source: srv.addr, Origin: "feed.test.", TsigKey: tsig}
	cfg := new(config.Config)
	cfg.RPZ = config.RPZ{Enabled: true, Mode: "enforce", Zones: []config.RPZZone{zc}}

	// New would start the live goroutine; build the placeholder store by
	// hand instead, exactly as New lays it out.
	r := &RPZ{enforce: true}
	r.zones = cfg.RPZ.Zones
	r.store.Store(&rpzengine.Store{Zones: []*rpzengine.Zone{{Name: "feed"}}})
	return r, newAXFRFeed(r, 0, zc)
}

func TestAXFRFeedEndToEnd(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")

	// Before the first transfer the zone filters nothing.
	if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("an empty feed filtered")
	}

	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	// The transferred rule enforces through the full middleware.
	if w, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); passed || w.Rcode() != dns.RcodeNameError {
		t.Fatalf("transferred rule did not act: passed=%v rcode=%d", passed, w.Rcode())
	}

	// A pushed update travels on the next cycle.
	srv.serial.Store(2)
	srv.setRules("fresh.example.com.feed.test. 300 IN CNAME rpz-drop.")
	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w, passed := serve(t, r, "fresh.example.com.", dns.TypeA, "udp", true); passed || w.Written() {
		t.Fatal("updated rule did not act")
	}
	if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("a rule removed by the update kept acting")
	}
}

func TestAXFRFeedRefusesSerialRollback(t *testing.T) {
	srv := startFeedServer(t, "", "")
	_, feed := feedUnderTest(t, srv, "")

	srv.serial.Store(10)
	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if feed.serial != 10 {
		t.Fatalf("installed serial = %d", feed.serial)
	}

	// The source rolls backwards; the probe refuses the cycle whole and
	// the installed copy stands. "Whole" is load-bearing: the transfer
	// must not even be attempted — a rejected source gets no second look
	// through a dearer channel (RFC 1982's refusal, layered once, at the
	// probe).
	before := srv.transfers.Load()
	srv.serial.Store(3)
	srv.setRules("evil.example.com.feed.test. 300 IN CNAME .")
	if err := feed.refreshOnce(context.Background()); err == nil {
		t.Fatal("a rollback cycle reported success")
	}
	if feed.serial != 10 {
		t.Fatalf("rollback moved the installed serial to %d", feed.serial)
	}
	if got := srv.transfers.Load() - before; got != 0 {
		t.Fatalf("the rollback cycle transferred %d times; the probe must refuse it whole", got)
	}
}

func TestAXFRFeedWithdrawsPastExpire(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")

	clock := time.Now()
	feed.now = func() time.Time { return clock }

	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w, _ := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !w.Written() {
		t.Fatal("rule not serving before expire")
	}

	// The source goes dark past the SOA expire (86400s): the next failed
	// cycle withdraws the rules, and resolution continues unfiltered.
	srv.serial.Store(0) // the serve loop still answers; force a failure via a dead source instead
	feed.source = "127.0.0.1:1"
	clock = clock.Add(87000 * time.Second)
	if err := feed.refreshOnce(context.Background()); err == nil {
		t.Fatal("a dead source reported success")
	}
	feed.maybeWithdraw()

	if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("expired feed kept enforcing")
	}

	// Inside the expire window the same failure keeps the rules serving.
	srv2 := startFeedServer(t, "", "")
	r2, feed2 := feedUnderTest(t, srv2, "")
	clock2 := time.Now()
	feed2.now = func() time.Time { return clock2 }
	if err := feed2.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	feed2.source = "127.0.0.1:1"
	clock2 = clock2.Add(3600 * time.Second)
	_ = feed2.refreshOnce(context.Background())
	feed2.maybeWithdraw()
	if w, _ := serve(t, r2, "blocked.example.com.", dns.TypeA, "udp", true); !w.Written() {
		t.Fatal("a failure inside the expire window dropped the rules")
	}
}

func TestAXFRFeedTSIG(t *testing.T) {
	const keyName, secret = "feedkey.", "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0" //nolint:gosec // G101 - loopback test fixture, not a credential
	srv := startFeedServer(t, keyName, secret)
	r, feed := feedUnderTest(t, srv, keyName+":hmac-sha256.:"+secret)

	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); passed || w.Rcode() != dns.RcodeNameError {
		t.Fatal("TSIG-fed rule did not act")
	}

	// The same primary refuses an unsigned transfer — proof the signature
	// was doing the admitting.
	_, unsigned := feedUnderTest(t, srv, "")
	if err := unsigned.refreshOnce(context.Background()); err == nil {
		t.Fatal("the TSIG primary accepted an unsigned transfer")
	}
}

// TestWithdrawnFeedRestoresOnEqualSerial pins the review's first P1: a
// source that comes back with the SAME serial after a withdrawal must be
// re-transferred — the equal-serial short-circuit is "nothing to do" only
// while the copy is actually serving.
func TestWithdrawnFeedRestoresOnEqualSerial(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")
	clock := time.Now()
	feed.now = func() time.Time { return clock }

	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// The source goes dark past expire; the rules are withdrawn.
	goodSource := feed.source
	feed.source = "127.0.0.1:1"
	clock = clock.Add(87000 * time.Second)
	_ = feed.refreshOnce(context.Background())
	feed.maybeWithdraw()
	if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("withdrawal did not happen")
	}

	// The provider recovers — same serial, nothing changed on its side.
	// The copy must be rebuilt anyway.
	feed.source = goodSource
	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); passed || w.Rcode() != dns.RcodeNameError {
		t.Fatal("a recovered equal-serial source left the zone empty forever")
	}
}

// TestNextWakeBounds pins the schedule clamps: a degenerate SOA cannot
// spin the loop, and a live copy's wake lands at its expire boundary.
func TestNextWakeBounds(t *testing.T) {
	base := time.Now()
	f := &axfrFeed{now: func() time.Time { return base }}

	// No copy yet: the initial retry pace, whatever the SOA said.
	if got := f.nextWake(true); got != axfrInitialRetry {
		t.Fatalf("no copy: %v", got)
	}

	// A zero refresh must not become a hot loop.
	f.haveCopy = true
	f.loaded = base
	f.refresh, f.retry, f.expire = 0, 0, 86400*time.Second
	if got := f.nextWake(false); got < minFeedInterval {
		t.Fatalf("zero refresh spun: %v", got)
	}
	// A tiny retry is floored.
	f.retry = time.Second
	if got := f.nextWake(true); got != minFeedInterval {
		t.Fatalf("tiny retry not floored: %v", got)
	}

	// The expire boundary caps the wake: with 10s of life left, a 900s
	// retry must not sleep through the withdrawal.
	f.retry = 900 * time.Second
	f.loaded = base.Add(-f.expire + 10*time.Second)
	if got := f.nextWake(true); got > 10*time.Second+expireGrace {
		t.Fatalf("wake %v sleeps past the expire boundary", got)
	}
	// Withdrawn: the cap no longer applies (nothing left to withdraw);
	// the feed keeps retrying at the SOA's own pace.
	f.withdrawn = true
	if got := f.nextWake(true); got != f.retry {
		t.Fatalf("withdrawn wake: %v", got)
	}
}

// startDripTSIGServer is a correctly signed primary that delivers one
// envelope every interval, indefinitely. Each envelope arrives well inside
// dns.Transfer's per-envelope read timeout, so only an absolute bound on
// the whole attempt can stop the stream — the review's exact scenario.
func startDripTSIGServer(t *testing.T, name, secret string, interval time.Duration) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	soa, err := dns.NewRR("feed.test. 300 IN SOA ns.feed.test. admin.feed.test. 1 3600 900 86400 300")
	if err != nil {
		t.Fatal(err)
	}

	mux := dns.NewServeMux()
	mux.HandleFunc("feed.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype != dns.TypeAXFR || req.IsTsig() == nil || w.TsigStatus() != nil {
			return
		}
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope)
		done := make(chan struct{})
		go func() { defer close(done); _ = tr.Out(w, req, ch) }()
		ch <- &dns.Envelope{RR: []dns.RR{soa}}
		for i := 0; ; i++ {
			rr, _ := dns.NewRR(fmt.Sprintf("drip%d.example.com.feed.test. 300 IN CNAME .", i))
			select {
			case ch <- &dns.Envelope{RR: []dns.RR{rr}}:
				time.Sleep(interval)
			case <-done:
				return
			}
		}
	})
	server := &dns.Server{Listener: l, Handler: mux, TsigSecret: map[string]string{name: secret}}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	return l.Addr().String()
}

// TestTSIGTransferHonorsItsDeadline pins the review's context finding: a
// signed source dripping envelopes just inside the per-envelope read
// timeout must not hold the attempt past its budget, and a cancelled
// context must cut it short.
func TestTSIGTransferHonorsItsDeadline(t *testing.T) {
	addr := startDripTSIGServer(t, "k.", "c2VjcmV0", 100*time.Millisecond)
	zc := config.RPZZone{Name: "drip", Source: addr, Origin: "feed.test.", TsigKey: "k.:hmac-sha256.:c2VjcmV0"}

	t.Run("attempt budget", func(t *testing.T) {
		f := newAXFRFeed(&RPZ{}, 0, zc)
		f.timeout = 500 * time.Millisecond
		start := time.Now()
		_, err := f.transferTSIG(context.Background())
		if elapsed := time.Since(start); err == nil || elapsed > 3*time.Second {
			t.Fatalf("drip ran %v past a 500ms budget (err=%v)", elapsed, err)
		}
	})

	t.Run("context cancellation", func(t *testing.T) {
		f := newAXFRFeed(&RPZ{}, 0, zc)
		f.timeout = time.Minute
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(200*time.Millisecond, cancel)
		start := time.Now()
		_, err := f.transferTSIG(ctx)
		if elapsed := time.Since(start); err == nil || elapsed > 3*time.Second {
			t.Fatalf("cancelled drip ran %v (err=%v)", elapsed, err)
		}
	})
}

// TestStaleReloadCannotOverwriteANewerOne pins the review's parse-race
// finding: a reload claim that has been superseded while its parse ran
// must not commit — the sequence check and the swap share the lock.
func TestStaleReloadCannotOverwriteANewerOne(t *testing.T) {
	path := writeZone(t, testZone)
	r := newRPZ(t, "enforce", config.RPZZone{Name: "test", File: path})

	// An old reload claims its sequence, and while "parsing", a newer
	// push arrives and completes.
	staleSeq := r.reloadSeq[0].Add(1)
	if err := os.WriteFile(path, []byte(`
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 99 3600 900 604800 300
newrule.example.com.rpz.test. IN CNAME .
`), 0o600); err != nil {
		t.Fatal(err)
	}
	r.reload(0)
	if w, _ := serve(t, r, "newrule.example.com.", dns.TypeA, "udp", true); !w.Written() {
		t.Fatal("the newer push did not install")
	}

	// The old parse finally finishes and tries to commit the old content.
	oldZone, err := rpzengine.LoadZone("test", strings.NewReader(testZone), "old", rpzengine.OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	if r.commitReload(0, staleSeq, oldZone) {
		t.Fatal("a superseded parse committed")
	}
	// The newer generation still serves.
	if w, _ := serve(t, r, "newrule.example.com.", dns.TypeA, "udp", true); !w.Written() {
		t.Fatal("the stale parse rolled the newer policy back")
	}
}
