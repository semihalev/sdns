package cache

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func persistConfig(t *testing.T, dir string) *config.Config {
	t.Helper()
	return &config.Config{CacheSize: 1024, Expire: 300, Directory: dir, CachePersist: true}
}

func anchorsOf(lines ...string) func() []dns.RR {
	return func() []dns.RR {
		out := make([]dns.RR, 0, len(lines))
		for _, l := range lines {
			rr, _ := dns.NewRR(l)
			out = append(out, rr)
		}
		return out
	}
}

const (
	anchorA = ". 172800 IN DNSKEY 257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="
	anchorB = ". 172800 IN DNSKEY 257 3 13 oJMRESz5E4gYzS/q6XDrvU1qMPYIjCWzJaOau8XNEZeqCYKD5ar0IRd8KqXXFJkqmVfRvMGPmM1x8fGAa2XhSA=="
)

// Persist writes the answers the cache holds, and a fresh cache under the
// same configuration restores them on Restore.
func TestPersistAndRestore(t *testing.T) {
	dir := t.TempDir()
	cfg := persistConfig(t, dir)

	before := New(cfg)
	before.SetTrustAnchors(anchorsOf(anchorA))
	before.store.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Time{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	before.Persist(ctx)
	if _, err := os.Stat(filepath.Join(dir, snapshotFile)); err != nil {
		t.Fatalf("no snapshot written: %v", err)
	}

	after := New(cfg)
	after.SetTrustAnchors(anchorsOf(anchorA))
	after.Restore()
	if storedEntry(after.store, "a.test.", false) == nil {
		t.Fatal("the saved answer was not restored")
	}
}

// A snapshot written under other trust anchors, or another upstream setup,
// is discarded whole.
func TestRestoreRefusesAnotherConfiguration(t *testing.T) {
	cases := []struct {
		name   string
		change func(cfg *config.Config)
		anchor string
	}{
		{"trust anchors", func(*config.Config) {}, anchorB},
		{"dnssec", func(cfg *config.Config) { cfg.DNSSEC = "off" }, anchorA},
		{"forwarders", func(cfg *config.Config) { cfg.ForwarderServers = []string{"192.0.2.53:53"} }, anchorA},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			cfg := persistConfig(t, dir)
			cfg.DNSSEC = "on"

			before := New(cfg)
			before.SetTrustAnchors(anchorsOf(anchorA))
			before.store.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Time{})
			before.Persist(context.Background())

			next := *cfg
			tc.change(&next)
			after := New(&next)
			after.SetTrustAnchors(anchorsOf(tc.anchor))
			after.Restore()
			if after.store.PositiveLen() != 0 {
				t.Fatal("a snapshot from another configuration was restored")
			}
		})
	}
}

func TestPersistOffWritesNothing(t *testing.T) {
	dir := t.TempDir()
	cfg := persistConfig(t, dir)
	cfg.CachePersist = false

	c := New(cfg)
	c.store.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Time{})
	c.Persist(context.Background())
	if _, err := os.Stat(filepath.Join(dir, snapshotFile)); !os.IsNotExist(err) {
		t.Fatalf("cache_persist off still wrote a snapshot: %v", err)
	}
}
