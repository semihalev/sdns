package resolver

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
	"github.com/semihalev/zlog/v2"
	"github.com/stretchr/testify/assert"
)

func makeTestConfig() *config.Config {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	cfg := new(config.Config)
	cfg.RootServers = []string{"192.5.5.241:53"}
	cfg.Root6Servers = []string{"[2001:500:2f::f]:53"}
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

	if !middleware.Ready() {
		middleware.Register("edns", func(cfg *config.Config) middleware.Handler { return edns.New(cfg) })
		middleware.Register("resolver", func(cfg *config.Config) middleware.Handler { return New(cfg) })
		middleware.Setup(cfg)
	}

	return cfg
}

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
	assert.Equal(t, "resolver", handler.Name())

	m := new(dns.Msg)
	m.SetQuestion("www.test.", dns.TypeA)
	r := handler.handle(ctx, m)
	assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	if assert.Equal(t, 1, len(r.Answer)) {
		assert.Equal(t, "192.0.2.10", r.Answer[0].(*dns.A).A.String())
	}
	assert.Equal(t, 1, queries("www.test."), "the answer must come off the wire once")

	// The same question again. Answers are cached by the cache middleware,
	// which this chain does not carry, so the resolver asks again — one
	// query, not a fresh walk.
	m = new(dns.Msg)
	m.SetQuestion("www.test.", dns.TypeA)
	r = handler.handle(ctx, m)
	assert.Equal(t, dns.RcodeSuccess, r.Rcode)
	assert.Equal(t, 1, len(r.Answer))
	assert.Equal(t, 2, queries("www.test."), "the repeat must cost exactly one more query")

	// A name the authority denies.
	m = new(dns.Msg)
	m.SetQuestion("absent.test.", dns.TypeA)
	r = handler.handle(ctx, m)
	assert.Equal(t, dns.RcodeNameError, r.Rcode)
	assert.Equal(t, 0, len(r.Answer))

	// Questions the handler answers on its own, without asking anyone.
	m = new(dns.Msg)
	m.SetQuestion(".", dns.TypeANY)
	r = handler.handle(ctx, m)
	assert.Equal(t, dns.RcodeNotImplemented, r.Rcode)

	m = new(dns.Msg)
	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = false
	r = handler.handle(ctx, m)
	assert.NotEqual(t, dns.RcodeServerFailure, r.Rcode)
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

	assert.Equal(t, true, len(resp.Ns) > 0)
}

func Test_HandlerServe(t *testing.T) {
	cfg := makeTestConfig()
	h := New(cfg)

	ch := middleware.NewChain([]middleware.Handler{})
	mw := mock.NewWriter("tcp", "127.0.0.1:0")

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	ch.Reset(mw, req)

	h.ServeDNS(context.Background(), ch)
	assert.Equal(t, true, ch.Writer.Written())
}
