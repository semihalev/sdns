package resolver

import (
	"net"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// silentRoot is a loopback address that takes queries and never answers,
// the root for a test that never resolves from it. A resolver requires
// roots and primes against them in the background; a real root there sends
// the test out to the network.
func silentRoot(tb testing.TB) string {
	tb.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { _ = packet.Close() })
	return packet.LocalAddr().String()
}

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
