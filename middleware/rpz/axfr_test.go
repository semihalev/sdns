package rpz

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/internal/mock"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
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
	// expire is the SOA expire the server advertises.
	expire atomic.Uint32
}

func (s *feedServer) soa() *dns.SOA {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: "feed.test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns.feed.test.",
		Mbox:    "admin.feed.test.",
		Serial:  s.serial.Load(),
		Refresh: 3600, Retry: 900, Expire: s.expire.Load(), Minttl: 300,
	}
}

func startFeedServer(t *testing.T, tsigName, tsigSecret string) *feedServer {
	t.Helper()
	s := &feedServer{t: t, tsigName: tsigName, tsigSecret: tsigSecret}
	s.serial.Store(1)
	s.expire.Store(86400)
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

// TestNextWakeBounds pins the schedule floor: a degenerate SOA cannot
// spin the loop.
func TestNextWakeBounds(t *testing.T) {
	f := &axfrFeed{}

	// No copy yet: the initial retry pace, whatever the SOA said.
	if got := f.nextWake(true); got != axfrInitialRetry {
		t.Fatalf("no copy: %v", got)
	}

	// A zero refresh must not become a hot loop.
	f.haveCopy = true
	f.refresh, f.retry = 0, 0
	if got := f.nextWake(false); got < minFeedInterval {
		t.Fatalf("zero refresh spun: %v", got)
	}
	// A tiny retry is floored; a sane one rules.
	f.retry = time.Second
	if got := f.nextWake(true); got != minFeedInterval {
		t.Fatalf("tiny retry not floored: %v", got)
	}
	f.retry = 900 * time.Second
	if got := f.nextWake(true); got != f.retry {
		t.Fatalf("sane retry overridden: %v", got)
	}
}

// TestSleepNeverDriftsPastExpire pins the review's deadline finding: the
// jitter applies to the SOA pace, never to the expire boundary — whatever
// the draw, the wake that must withdraw lands at the horizon.
func TestSleepNeverDriftsPastExpire(t *testing.T) {
	base := time.Now()
	f := &axfrFeed{
		now: func() time.Time { return base }, haveCopy: true,
		refresh: 3600 * time.Second, retry: 900 * time.Second, expire: 86400 * time.Second,
	}
	// 10s of life left against a 900s retry pace.
	f.loaded = base.Add(-f.expire + 10*time.Second)
	for range 200 {
		if got := f.sleepFor(true); got > 10*time.Second+expireGrace {
			t.Fatalf("sleep %v drifts past the expire boundary", got)
		}
	}
	// Withdrawn there is nothing left to withdraw: the SOA pace rules,
	// jitter included (±10% of 900s).
	f.withdrawn = true
	if got := f.sleepFor(true); got < 800*time.Second || got > 1000*time.Second {
		t.Fatalf("withdrawn sleep: %v", got)
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
	// The newer generation still serves, and its gauges stand: a refused
	// commit publishes nothing — metrics travel with the store swap,
	// inside the same critical section.
	if w, _ := serve(t, r, "newrule.example.com.", dns.TypeA, "udp", true); !w.Written() {
		t.Fatal("the stale parse rolled the newer policy back")
	}
	if got := testutil.ToFloat64(zoneRules.WithLabelValues("test", rpzengine.TriggerQNAME)); got != 1 {
		t.Fatalf("zone_rules gauge = %v after a refused commit; the newer generation's count was 1", got)
	}
}

// serveQuiet is serve without the testing plumbing, safe for concurrent
// readers: it reports a torn outcome instead of failing the test itself.
func serveQuiet(r *RPZ, qname string) (rcode int, written, passed bool, err error) {
	q := new(dns.Msg)
	q.SetQuestion(qname, dns.TypeA)
	q.RecursionDesired = true
	q.SetEdns0(1232, false)
	raw, perr := q.Pack()
	if perr != nil {
		return 0, false, false, perr
	}
	req := new(middleware.Request)
	if !req.ParseWire(raw, time.Now(), nil) {
		return 0, false, false, errors.New("ParseWire refused an eligible query")
	}
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		passed = true
		ch.Cancel()
	})
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	ch := middleware.NewChain([]middleware.Handler{r, next})
	ch.ResetWire(w, req)
	ch.Next(context.Background())
	return w.Rcode(), w.Written(), passed, nil
}

// TestExpiredCopyWithdrawsBeforeTheRefresh pins the cycle order: past the
// horizon the rules stop serving when the wake fires, not up to a
// transfer timeout later. The refresh here hangs against a silent
// source, and the withdrawal must be observable while it still hangs.
func TestExpiredCopyWithdrawsBeforeTheRefresh(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")
	clock := time.Now()
	feed.now = func() time.Time { return clock }
	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A source that accepts the connection and never answers.
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
			defer c.Close() //nolint:revive // freed at listener close; the test is the scope
		}
	}()
	feed.source = l.Addr().String()
	// The refresh hangs for this long; the poll window below must end
	// well before it so a late (wrongly ordered) withdrawal can never be
	// mistaken for the early one.
	feed.timeout = 1500 * time.Millisecond
	clock = clock.Add(87000 * time.Second) // past the 86400s expire

	done := make(chan struct{})
	go func() { defer close(done); feed.cycle(context.Background()) }()

	withdrawn := false
	for deadline := time.Now().Add(750 * time.Millisecond); time.Now().Before(deadline); {
		_, _, passed, err := serveQuiet(r, "blocked.example.com.")
		if err != nil {
			t.Fatal(err)
		}
		if passed {
			withdrawn = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !withdrawn {
		t.Fatal("stale rules kept enforcing while the refresh attempt was in flight")
	}
	select {
	case <-done:
		t.Fatal("the refresh attempt finished before the withdrawal was observed; the order is unproven")
	default:
	}
	<-done
}

// TestZeroExpireTransferIsRefused pins the review's horizon finding: a
// source declaring expire 0 would disable withdrawal outright, so the
// transfer is refused and the zone stays empty rather than gaining rules
// that could never be retired.
func TestZeroExpireTransferIsRefused(t *testing.T) {
	srv := startFeedServer(t, "", "")
	srv.expire.Store(0)
	r, feed := feedUnderTest(t, srv, "")

	err := feed.refreshOnce(context.Background())
	if err == nil || !strings.Contains(err.Error(), "expire 0") {
		t.Fatalf("zero-expire transfer not refused: %v", err)
	}
	if _, passed := serve(t, r, "blocked.example.com.", dns.TypeA, "udp", true); !passed {
		t.Fatal("a refused transfer installed rules")
	}
}

// TestTSIGTransferDoesNotLeakTheProducer pins the drain: a stream whose
// terminator SOA is not the last record of its envelope makes the
// consumer return while the producer still has a send ahead of it —
// without the drain, every such transfer strands the goroutine parked on
// the unbuffered envelope channel.
func TestTSIGTransferDoesNotLeakTheProducer(t *testing.T) {
	const keyName, secret = "leakkey.", "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0" //nolint:gosec // G101 - loopback test fixture, not a credential
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	soa, _ := dns.NewRR("feed.test. 300 IN SOA ns.feed.test. admin.feed.test. 1 3600 900 86400 300")
	rule, _ := dns.NewRR("blocked.example.com.feed.test. 300 IN CNAME .")
	junk, _ := dns.NewRR("trailing.example.com.feed.test. 300 IN CNAME .")

	mux := dns.NewServeMux()
	mux.HandleFunc("feed.test.", func(w dns.ResponseWriter, req *dns.Msg) {
		if req.Question[0].Qtype != dns.TypeAXFR || req.IsTsig() == nil || w.TsigStatus() != nil {
			return
		}
		tr := new(dns.Transfer)
		ch := make(chan *dns.Envelope, 2)
		// The closing SOA arrives mid-envelope: the consumer returns at
		// it, the producer reads on and parks on its next send.
		ch <- &dns.Envelope{RR: []dns.RR{soa, rule}}
		ch <- &dns.Envelope{RR: []dns.RR{soa, junk}}
		close(ch)
		_ = tr.Out(w, req, ch)
	})
	server := &dns.Server{Listener: l, Handler: mux, TsigSecret: map[string]string{keyName: secret}}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	zc := config.RPZZone{Name: "leak", Source: l.Addr().String(), Origin: "feed.test.", TsigKey: keyName + ":hmac-sha256.:" + secret}
	f := newAXFRFeed(&RPZ{}, 0, zc)

	before := runtime.NumGoroutine()
	const rounds = 8
	for range rounds {
		rrs, err := f.transferTSIG(context.Background())
		if err != nil || len(rrs) == 0 {
			t.Fatalf("transfer failed: %v", err)
		}
	}
	// Give stranded producers nothing to wait for; only a leak keeps the
	// count elevated by the full round count.
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); {
		if runtime.NumGoroutine()-before < rounds {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("goroutines grew by %d over %d transfers; the producer is leaking", runtime.NumGoroutine()-before, rounds)
}

// TestConcurrentSwapAndServe is the phase's exit criterion in code: one
// zone slot rewritten through both writer paths — the feed's swap and
// the watcher's sequenced commit — while readers serve through the
// middleware. Every response must be a whole generation (blocked by the
// installed rule or passed clean); -race owns the memory-order proof.
func TestConcurrentSwapAndServe(t *testing.T) {
	r := newRPZ(t, "enforce", config.RPZZone{Name: "test", File: writeZone(t, testZone)})
	// The same name carries a different action in each generation, so a
	// single response tells exactly which one answered: NXDOMAIN is X,
	// a Local Data answer is Y, and anything else — a pass, a blend — is
	// a torn store. Distinct per-generation names could not see that: a
	// store wrongly carrying both rules would still produce individually
	// valid outcomes.
	const zoneX = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 10 3600 900 604800 300
probe.example.com.rpz.test. IN CNAME .
`
	const zoneY = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 11 3600 900 604800 300
probe.example.com.rpz.test. IN A 203.0.113.99
`
	zx, err := rpzengine.LoadZone("test", strings.NewReader(zoneX), "x", rpzengine.OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}
	zy, err := rpzengine.LoadZone("test", strings.NewReader(zoneY), "y", rpzengine.OverrideGiven, "")
	if err != nil {
		t.Fatal(err)
	}

	// The probe name must resolve to a generation from the first query,
	// so X is installed before any reader starts.
	r.swapZone(0, zx)

	stop := make(chan struct{})
	torn := make(chan string, 8)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(stop)
		for start := time.Now(); time.Since(start) < 300*time.Millisecond; {
			r.swapZone(0, zx) // the feed's path
			seq := r.reloadSeq[0].Add(1)
			r.commitReload(0, seq, zy) // the watcher's path
		}
	}()
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for served := 0; ; served++ {
				select {
				case <-stop:
					if served == 0 {
						torn <- "reader finished without serving a single query"
					}
					return
				default:
				}
				rcode, _, passed, err := serveQuiet(r, "probe.example.com.")
				if err != nil {
					torn <- err.Error()
					return
				}
				if passed || (rcode != dns.RcodeNameError && rcode != dns.RcodeSuccess) {
					torn <- fmt.Sprintf("neither generation answered: passed=%v rcode=%d", passed, rcode)
					return
				}
			}
		}()
	}
	wg.Wait()
	select {
	case msg := <-torn:
		t.Fatal(msg)
	default:
	}
}

// TestRefreshAttemptCannotOutliveTheHorizon pins the review's P1: a
// cycle starting just inside the horizon must not let its refresh
// attempt keep stale rules serving past expire. The attempt is bounded
// by the copy's remaining trust — cancelled at the boundary, its failure
// path withdraws there, not a full transfer timeout later.
func TestRefreshAttemptCannotOutliveTheHorizon(t *testing.T) {
	srv := startFeedServer(t, "", "")
	r, feed := feedUnderTest(t, srv, "")
	if err := feed.refreshOnce(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A source that accepts the connection and never answers.
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
			defer c.Close() //nolint:revive // freed at listener close; the test is the scope
		}
	}()
	feed.source = l.Addr().String()
	feed.timeout = 30 * time.Second // the budget the horizon must beat

	// ~500ms of trust left, and the clock keeps running from there so
	// the horizon actually passes while the attempt is in flight.
	offset := 86400*time.Second - 500*time.Millisecond
	feed.now = func() time.Time { return time.Now().Add(offset) }

	began := time.Now()
	feed.cycle(context.Background())
	elapsed := time.Since(began)
	if elapsed > 5*time.Second {
		t.Fatalf("the attempt ran %v with the horizon 500ms away", elapsed)
	}
	if _, _, passed, err := serveQuiet(r, "blocked.example.com."); err != nil || !passed {
		t.Fatalf("rules still serving past the horizon (err=%v)", err)
	}
}
