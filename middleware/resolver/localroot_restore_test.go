package resolver

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware/resolver/localroot"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// savedRootCopy leaves a verified copy of a test root in a fresh state
// directory, the way a previous run's manager would have, and returns a
// configuration that trusts the zone's key and keeps its state there.
func savedRootCopy(t *testing.T) (*config.Config, *roottest.Zone) {
	t.Helper()
	z, err := roottest.Build(localroot.ComputeDigest)
	if err != nil {
		t.Fatal(err)
	}
	// Not TempDir: the resolver's background upkeep may write trust state
	// into the directory while the test's cleanup is removing it.
	dir, err := os.MkdirTemp("", "sdns-localroot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, localRootCopyFile)

	prev := localroot.New(nil, func() []dns.RR { return z.Anchors })
	prev.SetCopyPath(path)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Run only to start the disk writer; its first transfer is seconds away
	// and the context ends long before.
	go prev.Run(ctx)
	if err := prev.Load(z.RRs); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the previous run never wrote its copy")
		}
		time.Sleep(10 * time.Millisecond)
	}

	cfg := makeTestConfig()
	cfg.Directory = dir
	cfg.DNSSEC = "on"
	cfg.HyperlocalRoot = true
	cfg.RootKeys = []string{z.Key.String()}
	return cfg, z
}

// The copy an earlier run saved is serving by the time the resolver is
// built: the restore runs in NewResolver, ahead of the background upkeep
// and of the pipeline publish that lets queries in.
func TestNewResolverRestoresTheRootCopy(t *testing.T) {
	cfg, _ := savedRootCopy(t)

	r := NewResolver(cfg)

	s := r.localRoot.Load().Active()
	if s == nil {
		t.Fatal("the saved copy was not serving when NewResolver returned")
	}
	if s.Serial() != roottest.Serial {
		t.Fatalf("serial = %d, want %d", s.Serial(), roottest.Serial)
	}
}

// The copy is verified against the trust state on disk, not the configured
// seed: a key tombstoned by an earlier run cannot vouch for it, even though
// the configuration still names that key. The local root consumes the
// anchors with DNSSEC validation off as well, so both modes hold.
func TestNewResolverRestoresUnderTheTrustStateOnDisk(t *testing.T) {
	for _, mode := range []string{"on", "off"} {
		t.Run("dnssec "+mode, func(t *testing.T) {
			cfg, z := savedRootCopy(t)
			cfg.DNSSEC = mode
			if err := writeTombstones(filepath.Join(cfg.Directory, tombstoneFile), Tombstones{
				dnskeyMaterialFP(z.Key): {DNSKey: z.Key, FirstSeen: time.Now()},
			}); err != nil {
				t.Fatal(err)
			}

			r := NewResolver(cfg)

			if r.localRoot.Load().Active() != nil {
				t.Fatal("a copy was restored on the strength of a tombstoned key")
			}
		})
	}
}
