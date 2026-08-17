package resolver

import (
	"context"
	"math"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
	"github.com/semihalev/zlog/v2"
)

func makeTestConfig() *config.Config {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	// TEST-NET-1 (RFC 5737): reserved for documentation and routed nowhere.
	// The resolver primes its root list in the background as soon as it is
	// built, so a real root address here would send every test in this
	// package to the internet whether it wanted to go or not. Tests that
	// need a root that answers stand one up themselves — see hermetic_test.go.
	cfg.RootServers = []string{"192.0.2.1:53"}
	cfg.Root6Servers = nil
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	cfg.Maxdepth = 30
	cfg.Expire = 600
	cfg.CacheSize = 1024
	cfg.Timeout.Duration = 2 * time.Second
	cfg.Directory = filepath.Join(os.TempDir(), "sdns_temp")
	_ = os.MkdirAll(cfg.Directory, 0750)
	cfg.IPv6Access = true
	cfg.DNSSEC = "on"

	// Register once for the whole process. The Ready check alone is not a
	// guard: two parallel tests can both pass it and the second Register
	// panics with "edns already registered", which is why this shows up
	// when a single test is run by name and not in a full-package run.
	registerTestMiddleware.Do(func() {
		if middleware.Ready() {
			return
		}
		middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
		middleware.Register("resolver", func(cfg *config.Config) middleware.Handler { return New(cfg) })
		middleware.Setup(cfg)
	})

	return cfg
}

var registerTestMiddleware sync.Once

// startTestAuthority serves answers for the given questions from loopback.
// It replies authoritatively to everything it knows, so a resolver pointed
// at it as its root reaches an answer without walking a delegation: glue
// addresses always name port 53, which a test cannot bind unprivileged.
//
// The returned accessor reports how many queries reached the wire for one
// name. It counts per name on purpose: the resolver primes its root list
// from a background goroutine, so a total would fold that query into
// whichever window happened to be open when it landed.
func startTestAuthority(t *testing.T, zone map[string][]dns.RR) (string, func(string) int, func()) {
	t.Helper()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}

	var mu sync.Mutex
	queries := make(map[string]int)
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		if len(r.Question) == 1 {
			mu.Lock()
			queries[r.Question[0].Name]++
			mu.Unlock()
		}
		reply := new(dns.Msg)
		reply.SetReply(r)
		reply.Authoritative = true
		if len(r.Question) == 1 {
			if answers, ok := zone[r.Question[0].Name]; ok {
				for _, rr := range answers {
					if rr.Header().Rrtype == r.Question[0].Qtype {
						reply.Answer = append(reply.Answer, dns.Copy(rr))
					}
				}
			} else {
				reply.Rcode = dns.RcodeNameError
			}
		}
		_ = w.WriteMsg(reply)
	})

	server := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	time.Sleep(10 * time.Millisecond)

	count := func(name string) int {
		mu.Lock()
		defer mu.Unlock()
		return queries[name]
	}
	return pc.LocalAddr().String(), count, func() { _ = server.Shutdown() }
}

// Test_handler drives the handler's own behaviour — what it answers, what
// it costs upstream, and what it refuses — against a loopback authority.
//
// It used to resolve www.apple.com., dnssec-failed.org. and a dnscheck.tools
// probe from the live root, which made it fail for reasons that had nothing
// to do with this code: a network without working IPv6 burns the query
// budget on unreachable root servers, and third-party zones change their
// DNSSEC setup underneath the assertions.
func Test_handler(t *testing.T) {
	answer, err := dns.NewRR("www.test. 300 IN A 192.0.2.10")
	if err != nil {
		t.Fatalf("NewRR: %v", err)
	}
	addr, queries, stop := startTestAuthority(t, map[string][]dns.RR{
		"www.test.": {answer},
	})
	defer stop()

	cfg := makeTestConfig()
	cfg.RootServers = []string{addr}
	cfg.Root6Servers = nil
	cfg.IPv6Access = false
	cfg.DNSSEC = "off"

	ctx := context.Background()
	handler := New(cfg)
	if !reflect.DeepEqual("resolver", handler.Name()) {
		t.Errorf("handler.Name() = %v, want %v", handler.Name(), "resolver")
	}

	m := new(dns.Msg)
	m.SetQuestion("www.test.", dns.TypeA)
	r := handler.handle(ctx, m)
	if !reflect.DeepEqual(dns.RcodeSuccess, r.Rcode) {
		t.Errorf("r.Rcode = %v, want %v", r.Rcode, dns.RcodeSuccess)
	}
	if len(r.Answer) != 1 {
		t.Errorf("len(r.Answer) = %v, want %v", len(r.Answer), 1)
	} else if !reflect.DeepEqual("192.0.2.10", r.Answer[0].(*dns.A).A.String()) {
		t.Errorf("r.Answer[0].(*dns.A).A.String() = %v, want %v", r.Answer[0].(*dns.A).A.String(), "192.0.2.10")
	}
	if !reflect.DeepEqual(1, queries("www.test.")) {
		t.Errorf("%s: queries('www.test.') = %v, want %v", "the answer must come off the wire once", queries("www.test."), 1)
	}

	// The same question again. Answers are cached by the cache middleware,
	// which this chain does not carry, so the resolver asks again — one
	// query, not a fresh walk.
	m = new(dns.Msg)
	m.SetQuestion("www.test.", dns.TypeA)
	r = handler.handle(ctx, m)
	if !reflect.DeepEqual(dns.RcodeSuccess, r.Rcode) {
		t.Errorf("r.Rcode = %v, want %v", r.Rcode, dns.RcodeSuccess)
	}
	if !reflect.DeepEqual(1, len(r.Answer)) {
		t.Errorf("len(r.Answer) = %v, want %v", len(r.Answer), 1)
	}
	if !reflect.DeepEqual(2, queries("www.test.")) {
		t.Errorf("%s: queries('www.test.') = %v, want %v", "the repeat must cost exactly one more query", queries("www.test."), 2)
	}

	// A name the authority denies.
	m = new(dns.Msg)
	m.SetQuestion("absent.test.", dns.TypeA)
	r = handler.handle(ctx, m)
	if !reflect.DeepEqual(dns.RcodeNameError, r.Rcode) {
		t.Errorf("r.Rcode = %v, want %v", r.Rcode, dns.RcodeNameError)
	}
	if !reflect.DeepEqual(0, len(r.Answer)) {
		t.Errorf("len(r.Answer) = %v, want %v", len(r.Answer), 0)
	}

	// Questions the handler answers on its own, without asking anyone.
	m = new(dns.Msg)
	m.SetQuestion(".", dns.TypeANY)
	r = handler.handle(ctx, m)
	if !reflect.DeepEqual(dns.RcodeNotImplemented, r.Rcode) {
		t.Errorf("r.Rcode = %v, want %v", r.Rcode, dns.RcodeNotImplemented)
	}

	m = new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = false
	r = handler.handle(ctx, m)
	if reflect.DeepEqual(dns.RcodeServerFailure, r.Rcode) {
		t.Errorf("r.Rcode = %v, want a different value", r.Rcode)
	}
}

func Test_HandlerHINFO(t *testing.T) {
	ctx := context.Background()
	cfg := makeTestConfig()
	handler := New(cfg)

	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeHINFO)
	m.Question[0].Qclass = dns.ClassCHAOS

	debugns = true
	resp := handler.handle(ctx, m)

	if !reflect.DeepEqual(true, len(resp.Ns) > 0) {
		t.Errorf("len(resp.Ns) > 0 = %v, want %v", len(resp.Ns) > 0, true)
	}
}

func Test_HandlerServe(t *testing.T) {
	// Against the package's unroutable default roots this would spend the
	// whole query budget timing out before writing its SERVFAIL. A root that
	// answers keeps it about the handler writing a response at all.
	h := newHermeticNet(t).Handler()

	ch := middleware.NewChain([]middleware.Handler{})
	mw := mock.NewWriter("tcp", "127.0.0.1:0")

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	ch.Reset(mw, req)

	h.ServeDNS(context.Background(), ch)
	if !reflect.DeepEqual(true, ch.Writer.Written()) {
		t.Errorf("ch.Writer.Written() = %v, want %v", ch.Writer.Written(), true)
	}
}

func Test_withQueryDeadline(t *testing.T) {
	timeout := 10 * time.Second

	// A parent already bounded at or before the timeout is returned as is:
	// a child there could never fire first.
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, gotCancel := withQueryDeadline(bounded, timeout)
	if !reflect.DeepEqual(bounded, got) {
		t.Errorf("%s: got = %v, want %v", "an earlier-bounded parent must not grow a child", got, bounded)
	}
	parentDeadline, _ := bounded.Deadline()
	gotDeadline, ok := got.Deadline()
	if !(ok) {
		t.Errorf("ok is false")
	}
	if !reflect.DeepEqual(parentDeadline, gotDeadline) {
		t.Errorf("gotDeadline = %v, want %v", gotDeadline, parentDeadline)
	}
	gotCancel()
	if err := bounded.Err(); err != nil {
		t.Errorf("%s: unexpected error: %v", "the no-op cancel must not cancel the parent", err)
	}

	// An unbounded parent gets the timeout.
	got, gotCancel = withQueryDeadline(context.Background(), timeout)
	defer gotCancel()
	gotDeadline, ok = got.Deadline()
	if !(ok) {
		t.Errorf("%s: ok is false", "an unbounded parent must gain a deadline")
	}
	if diff := math.Abs(time.Until(gotDeadline).Seconds() - timeout.Seconds()); diff > 1.0 {
		t.Errorf("deadline is %v seconds away, want within 1.0 of %v", time.Until(gotDeadline).Seconds(), timeout.Seconds())
	}

	// A parent bounded later than the timeout is tightened.
	loose, cancel2 := context.WithTimeout(context.Background(), time.Hour)
	defer cancel2()
	got, gotCancel = withQueryDeadline(loose, timeout)
	defer gotCancel()
	gotDeadline, _ = got.Deadline()
	looseDeadline, _ := loose.Deadline()
	if !(gotDeadline.Before(looseDeadline)) {
		t.Errorf("%s: gotDeadline.Before(looseDeadline) is false", "a later-bounded parent must be tightened")
	}
}

func Test_requestIDFromContext(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Second)
	defer lazy.Cancel()

	if !contextutil.TryPinValue(lazy, contextKeyRequestID, uint16(0xBEEF)) {
		t.Fatal("pin failed")
	}
	if got := requestIDFromContext(lazy); got != uint16(0xBEEF) {
		t.Fatalf("pinned request ID = %v, want 0xBEEF", got)
	}

	// A detached context carries the ID as an ordinary value node.
	detached := context.WithValue(context.Background(), contextKeyRequestID, uint16(0xCAFE))
	if got := requestIDFromContext(detached); got != uint16(0xCAFE) {
		t.Fatalf("value-carried request ID = %v, want 0xCAFE", got)
	}
	if got := requestIDFromContext(context.Background()); got != nil {
		t.Fatalf("empty context yielded %v", got)
	}
}

// Test_withQueryDeadline_LazyParentAllocsNothing pins the point of the guard:
// the server bounds every request with a LazyDeadline at entry, so the
// handler's per-request query-timeout derivation must be free on that path.
func Test_withQueryDeadline_LazyParentAllocsNothing(t *testing.T) {
	parent := contextutil.WithLazyTimeout(context.Background(), time.Second)
	defer parent.Cancel()

	allocs := testing.AllocsPerRun(100, func() {
		ctx, cancel := withQueryDeadline(parent, 10*time.Second)
		cancel()
		_ = ctx
	})
	if allocs != 0 {
		t.Errorf("%s: allocs = %v, want 0", "deriving the query deadline under a server-bounded parent must not allocate", allocs)
	}
}
