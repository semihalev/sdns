package resolver

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/resolver/localroot"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// An answer resolved under the hyperlocal root is saved at shutdown and
// restored at the next start like any other: cache_persist must not go
// quiet because the root came from a local copy. The control resolves the
// same name through the root server on the wire.
func TestLocalRootAnswersSurviveARestart(t *testing.T) {
	for _, tc := range []struct {
		name      string
		localRoot bool
	}{{"root on the wire", false}, {"hyperlocal root", true}} {
		t.Run(tc.name, func(t *testing.T) {
			net := newHermeticNet(t)
			zone := net.DelegateInsecure("snap.")
			zone.Serve(mustRR(t, "www.snap. 300 IN A 192.0.2.44"))

			cfg := net.Config()
			cfg.CacheSize = 1024
			cfg.CachePersist = true
			cfg.Directory = t.TempDir()
			handler := net.handlerWithConfig(cfg)
			if tc.localRoot {
				z, err := roottest.BuildZone(localroot.ComputeDigest, []string{
					fmt.Sprintf(". 86400 IN SOA a.root-servers.test. nstld.test. %d 1800 900 604800 86400", roottest.Serial),
					". 518400 IN NS a.root-servers.test.",
					". 86400 IN NSEC snap. NS SOA RRSIG NSEC DNSKEY ZONEMD",
					"snap. 172800 IN NS ns.snap.",
					"snap. 86400 IN NSEC . NS RRSIG NSEC",
					"a.root-servers.test. 172800 IN A 198.51.100.53",
					"ns.snap. 172800 IN A " + zone.glue.String(),
				}, roottest.Serial)
				if err != nil {
					t.Fatal(err)
				}
				mgr := localroot.New(nil, func() []dns.RR { return z.Anchors })
				if err := mgr.Load(z.RRs); err != nil {
					t.Fatal(err)
				}
				handler.resolver.localRoot.Store(mgr)
			}

			ask := func(handlers []middleware.Handler) *dns.Msg {
				t.Helper()
				req := new(dns.Msg)
				req.SetQuestion("www.snap.", dns.TypeA)
				writer := mock.NewWriter("udp", "127.0.0.1:0")
				ch := middleware.NewChain(handlers)
				ch.Reset(writer, req)
				ch.Next(context.Background())
				return writer.Msg()
			}

			saving := answercache.New(cfg)
			handlers := []middleware.Handler{saving, handler}
			var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
			handler.resolver.queryer.Store(&queryer)
			if resp := ask(handlers); resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
				t.Fatalf("the name did not resolve: %v", resp)
			}
			if tc.localRoot && net.root.asked("snap.", dns.TypeNS)+net.root.asked("www.snap.", dns.TypeA) != 0 {
				t.Fatal("the root on the wire was asked, the hyperlocal root was not used")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			saving.Persist(ctx)
			cancel()

			restored := answercache.New(cfg)
			restored.Restore()
			asked := zone.asked("www.snap.", dns.TypeA)
			if resp := ask([]middleware.Handler{restored, handler}); resp == nil || len(resp.Answer) == 0 {
				t.Fatalf("no answer after the restart: %v", resp)
			}
			if zone.asked("www.snap.", dns.TypeA) != asked {
				t.Fatal("the answer was not restored, the zone was asked again")
			}
		})
	}
}
