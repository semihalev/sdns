package resolver

import (
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// newWiredTestResolver constructs a fresh Resolver and inherits the
// queryer / store from the DNSHandler that middleware.Setup already
// wired. Tests in this package construct Resolvers outside the
// pipeline to test internal behaviour in isolation; without this
// helper their internal NS lookups would fail with "queryer not
// wired" because the auto-wiring only reaches handlers registered
// with the pipeline.
func newWiredTestResolver(cfg *config.Config) *Resolver {
	r := NewResolver(cfg)
	if pipe := middleware.GlobalPipeline(); pipe != nil {
		if dh, ok := pipe.Get("resolver").(*DNSHandler); ok && dh.resolver != nil {
			if q := dh.resolver.queryer.Load(); q != nil {
				r.queryer.Store(q)
			}
			if s := dh.resolver.store.Load(); s != nil {
				r.store.Store(s)
			}
		}
	}
	return r
}
