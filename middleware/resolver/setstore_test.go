package resolver

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/middleware"
)

// stubStore implements middleware.Store with no-op semantics.
type stubStore struct{}

func (stubStore) Get(*dns.Msg) (*dns.Msg, bool)  { return nil, false }
func (stubStore) SetFromResponse(*dns.Msg, bool) {}

// TestDNSHandlerSetStore pins that SetStore installs the store on
// the underlying Resolver so subQuery can consult it. Auto-wired
// in production via middleware.StoreSetter discovery. Uses a bare
// Resolver{} to avoid NewResolver's background priming goroutine,
// which zlog.Fatal's on empty root servers.
func TestDNSHandlerSetStore(t *testing.T) {
	h := &DNSHandler{resolver: &Resolver{}}

	var s middleware.Store = stubStore{}
	h.SetStore(s)

	got := h.resolver.store.Load()
	if got == nil {
		t.Fatal("SetStore did not install the store on the Resolver")
	}
	if *got != s {
		t.Fatal("installed store does not match the one passed to SetStore")
	}
}

// TestDNSHandlerPurge pins the middleware.Purger adapter: only
// TypeNS questions touch the resolver's NS cache; other qtypes are
// no-ops. Uses a bare Resolver{} populated with only the ncache to
// skip NewResolver's background priming.
func TestDNSHandlerPurge(t *testing.T) {
	h := &DNSHandler{resolver: &Resolver{ncache: authcache.NewNSCache()}}

	nsQuestion := dns.Question{Name: "example.com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}
	servers := new(authcache.AuthServers)
	servers.Zone = "example.com."
	h.resolver.ncache.Set(cache.Key(nsQuestion, false), nil, servers, 60*time.Second)
	h.resolver.ncache.Set(cache.Key(nsQuestion, true), nil, servers, 60*time.Second)

	// Non-NS qtype: must be a no-op.
	h.Purge(dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	if _, err := h.resolver.ncache.Get(cache.Key(nsQuestion, false)); err != nil {
		t.Fatal("Purge on TypeA must not evict NS cache entry")
	}

	// NS qtype: clears both CD variants.
	h.Purge(nsQuestion)
	if _, err := h.resolver.ncache.Get(cache.Key(nsQuestion, false)); err == nil {
		t.Fatal("Purge on TypeNS must evict CD=false entry")
	}
	if _, err := h.resolver.ncache.Get(cache.Key(nsQuestion, true)); err == nil {
		t.Fatal("Purge on TypeNS must evict CD=true entry")
	}
}
