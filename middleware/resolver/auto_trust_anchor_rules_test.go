package resolver

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

// These tests pin the rules AutoTA keeps while it reads trust state from
// disk, before and around the network refresh. They drive AutoTA directly
// against a loopback root, so the resolver runs with DNSSEC off: that keeps
// its background upkeep from running a second AutoTA over the same files
// while the test does, and AutoTA validates the fetched keys itself either
// way.

func autoTAResolver(t *testing.T) (*Resolver, *hermeticNet) {
	t.Helper()
	n := newHermeticNet(t)
	cfg := n.Config()
	cfg.DNSSEC = "off"
	return n.handlerWithConfig(cfg).resolver, n
}

func liveRootKeys(r *Resolver) []dns.RR {
	r.RLock()
	defer r.RUnlock()
	return slices.Clone(r.rootKeys)
}

func holdsKey(rrs []dns.RR, key *dns.DNSKEY) bool {
	for _, rr := range rrs {
		if k, ok := rr.(*dns.DNSKEY); ok && dnskeyMaterialFP(k) == dnskeyMaterialFP(key) {
			return true
		}
	}
	return false
}

func writeTAState(t *testing.T, r *Resolver, anchors ...*TrustAnchor) string {
	t.Helper()
	state := make(TrustAnchors, len(anchors))
	for _, ta := range anchors {
		state[dnssec.KeyTag(ta.DNSKey)] = ta
	}
	path := filepath.Join(r.cfg.Directory, stateFile)
	if err := writeToTAFile(path, state); err != nil {
		t.Fatalf("write trust anchor state: %v", err)
	}
	return path
}

// breakRootDNSKEY makes the root's DNSKEY RRset fail validation against the
// configured anchor, so a refresh stops right after the fetch.
func breakRootDNSKEY(t *testing.T, n *hermeticNet) {
	t.Helper()
	other := newHermeticKey(t, ".")
	n.root.serve(".", dns.TypeDNSKEY, n.rootKey.key, other.sign(t, []dns.RR{n.rootKey.key}))
}

// A tombstones file that reads but does not decode may be hiding a
// revocation, so the whole trust set is dropped, and nothing is fetched or
// written on top of it.
func TestAutoTACorruptTombstonesFailClosed(t *testing.T) {
	r, n := autoTAResolver(t)
	statePath := writeTAState(t, r, &TrustAnchor{DNSKey: n.rootKey.key, State: StateValid, FirstSeen: time.Now()})
	before, err := os.ReadFile(statePath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.cfg.Directory, tombstoneFile), []byte("not a gob stream"), 0o600); err != nil {
		t.Fatal(err)
	}

	r.AutoTA()

	if keys := liveRootKeys(r); len(keys) != 0 {
		t.Fatalf("corrupt tombstones left %d trust anchors live, want none", len(keys))
	}
	if n.root.asked(".", dns.TypeDNSKEY) != 0 {
		t.Fatal("a refresh that failed closed on corrupt tombstones still fetched the root DNSKEY")
	}
	after, err := os.ReadFile(statePath) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refresh that failed closed rewrote the trust anchor state")
	}
}

// The trust set AutoTA publishes from disk before its fetch is only ever a
// narrowing of what is already live. An empty live set means an earlier run
// failed closed, and disk may still name the key whose revocation was seen
// only in memory, so disk must not bring it back; a later refresh that
// persists its outcome is what may.
func TestAutoTAPublishesFromDiskOnlyOverALiveSet(t *testing.T) {
	t.Run("fail-closed stays closed", func(t *testing.T) {
		r, n := autoTAResolver(t)
		writeTAState(t, r, &TrustAnchor{DNSKey: n.rootKey.key, State: StateValid, FirstSeen: time.Now()})
		breakRootDNSKEY(t, n)
		r.Lock()
		r.rootKeys = nil
		r.Unlock()

		r.AutoTA()

		if n.root.asked(".", dns.TypeDNSKEY) == 0 {
			t.Fatal("the refresh never reached its fetch, so the pre-fetch publish was not exercised")
		}
		if keys := liveRootKeys(r); len(keys) != 0 {
			t.Fatalf("a failed-closed trust set was republished from disk: %d anchors live", len(keys))
		}
	})

	t.Run("live set narrows to the tombstone-filtered disk state", func(t *testing.T) {
		r, n := autoTAResolver(t)
		revoked := newHermeticKey(t, ".").key
		r.Lock()
		r.rootKeys = append(r.rootKeys, revoked)
		r.configuredRootKeys = append(r.configuredRootKeys, revoked)
		r.Unlock()
		writeTAState(t, r,
			&TrustAnchor{DNSKey: n.rootKey.key, State: StateValid, FirstSeen: time.Now()},
			&TrustAnchor{DNSKey: revoked, State: StateValid, FirstSeen: time.Now()},
		)
		if err := writeTombstones(filepath.Join(r.cfg.Directory, tombstoneFile), Tombstones{
			dnskeyMaterialFP(revoked): {DNSKey: revoked, FirstSeen: time.Now()},
		}); err != nil {
			t.Fatal(err)
		}
		breakRootDNSKEY(t, n)

		r.AutoTA()

		keys := liveRootKeys(r)
		if holdsKey(keys, revoked) {
			t.Fatal("a tombstoned key stayed trusted after a refresh whose fetch failed")
		}
		if !holdsKey(keys, n.rootKey.key) {
			t.Fatal("the untombstoned anchor was dropped from the live set")
		}
	})
}

// A revocation recorded only as a StateRevoked marker in the state file
// keeps that marker until the tombstones file holding it is durable. If the
// tombstones write fails, the marker is the only record of the revocation
// left on disk.
func TestAutoTAKeepsRevocationMarkerUntilTombstonePersists(t *testing.T) {
	markerState := func(t *testing.T, r *Resolver, n *hermeticNet) (string, *dns.DNSKEY) {
		t.Helper()
		revoked := newHermeticKey(t, ".").key
		revoked.Flags |= DNSKEYFlagRevoke
		path := writeTAState(t, r,
			&TrustAnchor{DNSKey: n.rootKey.key, State: StateValid, FirstSeen: time.Now()},
			&TrustAnchor{DNSKey: revoked, State: StateRevoked, FirstSeen: time.Now()},
		)
		return path, revoked
	}
	hasMarker := func(t *testing.T, path string, key *dns.DNSKEY) bool {
		t.Helper()
		state, err := readFromTAFile(path)
		if err != nil {
			t.Fatalf("read trust anchor state: %v", err)
		}
		ta := state[dnssec.KeyTag(key)]
		return ta != nil && ta.State == StateRevoked
	}

	t.Run("tombstones write fails", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root reads a mode 000 directory, so the tombstones path cannot be made unreadable")
		}
		r, n := autoTAResolver(t)
		statePath, revoked := markerState(t, r, n)
		// A directory the process cannot open reads as a transient failure,
		// not corruption, and a file cannot be renamed over it, so the
		// refresh runs to its writes and only the tombstones write fails.
		tombPath := filepath.Join(r.cfg.Directory, tombstoneFile)
		if err := os.Mkdir(tombPath, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(tombPath, 0o700) }) //nolint:gosec // test-owned temp dir

		r.AutoTA()

		if !hasMarker(t, statePath, revoked) {
			t.Fatal("the revocation marker was dropped although its tombstone was never written")
		}
		keys := liveRootKeys(r)
		if holdsKey(keys, revoked) {
			t.Fatal("the revoked key became trusted")
		}
		if !holdsKey(keys, n.rootKey.key) {
			t.Fatal("the refresh did not publish the persisted trust set")
		}
	})

	t.Run("tombstones write succeeds", func(t *testing.T) {
		r, n := autoTAResolver(t)
		statePath, revoked := markerState(t, r, n)

		r.AutoTA()

		if hasMarker(t, statePath, revoked) {
			t.Fatal("the revocation marker outlived its now durable tombstone")
		}
		tombstones, err := readTombstones(filepath.Join(r.cfg.Directory, tombstoneFile))
		if err != nil {
			t.Fatal(err)
		}
		if tombstones[dnskeyMaterialFP(revoked)] == nil {
			t.Fatal("the marker was dropped without its tombstone reaching disk")
		}
	})
}
