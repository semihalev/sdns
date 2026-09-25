package cache

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/sdns/internal/atomicfile"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
	"github.com/semihalev/zlog/v2"
)

const (
	snapshotFile = "cache.snapshot"

	// restoreBudget bounds the startup restore, both passes together. It
	// is checked between records, so a stalled disk can hold startup
	// longer; under ordinary disk access it is the bound.
	restoreBudget = 10 * time.Second
)

var (
	metricSnapshotEntries = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_cache_snapshot_entries_total",
		Help: "Cache answers saved at shutdown and loaded at startup, and those passed over, by operation and result",
	}, []string{"op", "result"})
	metricSnapshotSeconds = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_cache_snapshot_seconds",
		Help: "Duration of the last cache save or load, by operation and outcome",
	}, []string{"op", "outcome"})
)

// SetTrustAnchors implements middleware.TrustAnchorSetter.
func (c *Cache) SetTrustAnchors(anchors func() []dns.RR) { c.trustAnchors = anchors }

func (c *Cache) snapshotPath() string {
	return filepath.Join(c.cfg.Directory, snapshotFile)
}

// Restore implements middleware.Restorer: with cache_persist on, it loads
// the answers the previous run saved. Any failure leaves the cache empty,
// as on any other start.
func (c *Cache) Restore() {
	if !c.cfg.CachePersist {
		return
	}
	start := time.Now()
	loaded, err := c.restoreSnapshot(start)
	outcome := "ok"
	switch {
	case errors.Is(err, os.ErrNotExist):
		return
	case err != nil:
		outcome = "discarded"
		zlog.Warn("Saved cache not used", "path", c.snapshotPath(), "error", err.Error())
	}
	elapsed := time.Since(start)
	metricSnapshotSeconds.WithLabelValues("load", outcome).Set(elapsed.Seconds())
	metricSnapshotEntries.WithLabelValues("load", "loaded").Add(float64(loaded.loaded))
	metricSnapshotEntries.WithLabelValues("load", "expired").Add(float64(loaded.expired))
	metricSnapshotEntries.WithLabelValues("load", "refused").Add(float64(loaded.refused))
	if outcome == "ok" {
		zlog.Info("Cache restored", "path", c.snapshotPath(), "loaded", loaded.loaded,
			"expired", loaded.expired, "refused", loaded.refused, "full", loaded.full,
			"duration", elapsed.Round(time.Millisecond).String())
	}
}

func (c *Cache) restoreSnapshot(start time.Time) (snapshotLoaded, error) {
	f, err := os.Open(c.snapshotPath())
	if err != nil {
		return snapshotLoaded{}, err
	}
	defer f.Close() //nolint:errcheck // read-only
	deadline := start.Add(restoreBudget)
	return c.store.restore(f, c.snapshotFingerprint(), func(n uint64) bool {
		return n%1024 == 0 && time.Now().After(deadline)
	}, time.Now)
}

// Persist implements middleware.Persister: with cache_persist on, it saves
// the answer cache. When ctx is done no further answer is written and the
// file is finished with those already in it.
func (c *Cache) Persist(ctx context.Context) {
	if !c.cfg.CachePersist {
		return
	}
	walkUntil, ok := ctx.Deadline()
	if !ok {
		walkUntil = time.Now().Add(time.Hour)
	}
	start := time.Now()
	var saved snapshotSaved
	err := atomicfile.Write(c.snapshotPath(), func(w io.Writer) error {
		var err error
		saved, err = c.store.snapshot(w, c.snapshotFingerprint(), snapshotLZ4, start, func(i int) bool {
			return i%1024 == 0 && time.Now().After(walkUntil)
		})
		return err
	})
	elapsed := time.Since(start)
	if err != nil {
		metricSnapshotSeconds.WithLabelValues("save", "error").Set(elapsed.Seconds())
		zlog.Error("Cache save failed", "path", c.snapshotPath(), "error", err.Error())
		return
	}
	outcome := "ok"
	if saved.truncated {
		outcome = "truncated"
	}
	metricSnapshotSeconds.WithLabelValues("save", outcome).Set(elapsed.Seconds())
	metricSnapshotEntries.WithLabelValues("save", "saved").Add(float64(saved.saved))
	metricSnapshotEntries.WithLabelValues("save", "short").Add(float64(saved.short))
	metricSnapshotEntries.WithLabelValues("save", "scoped").Add(float64(saved.scoped))
	zlog.Info("Cache saved", "path", c.snapshotPath(), "saved", saved.saved,
		"truncated", saved.truncated, "duration", elapsed.Round(time.Millisecond).String())
}

// validatorSupport lists the DNSSEC algorithms and DS digest types the
// validator can verify. A zone signed only with something outside them is
// treated as unsigned, so an answer a build cached as insecure because it
// did not know the algorithm, a forged one included, must not be restored
// into a build that does: it would be served without ever meeting the
// check that would refuse it. A build that learns an algorithm, or one that
// loses or gains it with the FIPS module it is built against, changes these
// lists and the fingerprint with them.
var validatorSupport = func() (algorithms, digests []string) {
	for i := range 256 {
		n := uint8(i) //nolint:gosec // bounded by the range
		if dnssec.IsSupportedDNSKEYAlgorithm(n) {
			algorithms = append(algorithms, strconv.Itoa(i))
		}
		if dnssec.IsSupportedDSDigest(n) {
			digests = append(digests, strconv.Itoa(i))
		}
	}
	return algorithms, digests
}

// snapshotFingerprint names the configuration a saved cache is valid
// under: what decides which answers the cache is handed and whether they
// were validated. A snapshot written under another is discarded whole.
// Limits such as cachesize or maxttl are not part of it, a restore applies
// the current ones to every answer.
func (c *Cache) snapshotFingerprint() [32]byte {
	h := sha256.New()
	field := func(name string, values ...string) {
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(values))
		for _, v := range values {
			_, _ = io.WriteString(h, v)
			_, _ = h.Write([]byte{0})
		}
	}
	cfg := c.cfg
	field("format", fmt.Sprint(snapshotVersion))
	field("dnssec", cfg.DNSSEC)
	field("rootservers", cfg.RootServers...)
	field("root6servers", cfg.Root6Servers...)
	field("fallbackservers", cfg.FallbackServers...)
	field("forwarderservers", cfg.ForwarderServers...)
	zones := make([]string, 0, len(cfg.ForwardZones))
	for _, z := range cfg.ForwardZones {
		zones = append(zones, fmt.Sprintf("%+v", z))
	}
	field("forwardzones", zones...)
	field("emptyzones", cfg.EmptyZones...)

	var anchors []string
	if c.trustAnchors != nil {
		for _, rr := range c.trustAnchors() {
			if rr == nil {
				continue
			}
			// A key's TTL and the spelling of its owner name are not part of
			// its identity; its key material is, byte for byte, Base64 case
			// included.
			id := dns.Copy(rr)
			id.Header().Ttl = 0
			id.Header().Name = dns.CanonicalName(id.Header().Name)
			anchors = append(anchors, id.String())
		}
		sort.Strings(anchors)
	}
	field("trustanchors", anchors...)

	algorithms, digests := validatorSupport()
	field("dnssecalgorithms", algorithms...)
	field("dsdigests", digests...)

	var fp [32]byte
	h.Sum(fp[:0])
	return fp
}
