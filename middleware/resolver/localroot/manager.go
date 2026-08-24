package localroot

import (
	"context"
	"math/rand/v2"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/zlog/v2"
)

// DefaultSources are the root servers and ICANN hosts that publish the root
// zone over AXFR (RFC 8806 appendix A).
var DefaultSources = []string{
	"b.root-servers.net:53",
	"c.root-servers.net:53",
	"f.root-servers.net:53",
	"g.root-servers.net:53",
	"k.root-servers.net:53",
	"xfr.cjr.dns.icann.org:53",
	"xfr.lax.dns.icann.org:53",
}

var (
	metricAge = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "dns_localroot_copy_age_seconds",
		Help: "Age of the active local root zone copy; -1 when none is active",
	})
	metricTransfers = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_localroot_transfers_total",
		Help: "Root zone transfer attempts by outcome",
	}, []string{"outcome"})
	metricAnswers = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_localroot_answers_total",
		Help: "Walk consultations answered from the local root copy",
	}, []string{"kind"})
)

// CountReferral, CountDenial, CountDS and CountFallback attribute walk
// consultations on the resolver side without exporting the metric vec.
func CountReferral() { metricAnswers.WithLabelValues("referral").Inc() }

// CountDenial counts an NXDOMAIN synthesized from the local copy.
func CountDenial() { metricAnswers.WithLabelValues("denial").Inc() }

// CountDS counts a DS answer served from the local copy.
func CountDS() { metricAnswers.WithLabelValues("ds").Inc() }

// CountFallback counts a root consult that fell back to the real root
// servers because no verified copy was active.
func CountFallback() { metricAnswers.WithLabelValues("fallback").Inc() }

// Manager owns the verified snapshot and its refresh lifecycle. Refresh
// follows the zone's own SOA schedule (RFC 8806 defers to RFC 1035
// secondary semantics): probe the serial every REFRESH seconds, fall to
// RETRY on failure, and never serve a copy past EXPIRE — Active goes nil
// and the resolver walks to the real roots.
type Manager struct {
	sources []string
	anchors func() []dns.RR // trust anchors as a DS set; empty = cannot verify
	timeout time.Duration

	snap atomic.Pointer[Snapshot]

	// now/transferFn/probeFn are the test seams; production uses the
	// package functions and the wall clock.
	now        func() time.Time
	transferFn func(ctx context.Context, addr string, timeout time.Duration) ([]dns.RR, error)
	probeFn    func(ctx context.Context, addr string, timeout time.Duration) (uint32, error)
}

// New builds a Manager over the given transfer sources (DefaultSources when
// empty) and a trust-anchor supplier.
func New(sources []string, anchors func() []dns.RR) *Manager {
	if len(sources) == 0 {
		sources = DefaultSources
	}
	return &Manager{
		sources:    sources,
		anchors:    anchors,
		timeout:    30 * time.Second,
		now:        time.Now,
		transferFn: axfr,
		probeFn:    probeSerial,
	}
}

// Active returns the verified snapshot to serve from, or nil when there is
// none — never transferred, or the copy has outlived its SOA expire.
func (m *Manager) Active() *Snapshot {
	s := m.snap.Load()
	if s == nil || s.Expired(m.now()) {
		return nil
	}
	return s
}

// Run drives the refresh loop until ctx is cancelled. The first transfer is
// attempted immediately; afterwards the loop probes the serial on the SOA
// refresh interval (jittered ±10%) and transfers only on change, retrying
// on the SOA retry interval after any failure.
func (m *Manager) Run(ctx context.Context) {
	const (
		fallbackRefresh = 30 * time.Minute
		fallbackRetry   = 15 * time.Minute
	)

	next := time.Duration(0) // immediate first attempt
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(jitter(next)):
		}

		cur := m.snap.Load()
		refresh, retry := fallbackRefresh, fallbackRetry
		if cur != nil {
			refresh = time.Duration(cur.soa.Refresh) * time.Second
			retry = time.Duration(cur.soa.Retry) * time.Second
		}

		if err := m.refreshOnce(ctx); err != nil {
			zlog.Warn("Local root refresh failed", "error", err.Error())
			next = retry
		} else {
			next = refresh
		}

		if s := m.Active(); s != nil {
			metricAge.Set(m.now().Sub(s.Loaded()).Seconds())
		} else {
			metricAge.Set(-1)
		}
	}
}

// refreshOnce probes for a serial change and transfers when one is seen (or
// when no copy exists yet). Sources rotate: the probe's source is the
// transfer's source, so a host that cannot answer is skipped whole.
func (m *Manager) refreshOnce(ctx context.Context) error {
	cur := m.snap.Load()

	var lastErr error
	for _, addr := range m.sources {
		if cur != nil {
			serial, err := m.probeFn(ctx, addr, m.timeout)
			if err != nil {
				lastErr = err
				continue
			}
			if serial == cur.serial {
				// Current: touch nothing. The copy's expire horizon is
				// anchored at its transfer; a probe is not a transfer.
				// Transfer again once the copy has spent half its
				// expire interval, so the horizon keeps moving on a
				// healthy source well before it threatens.
				if m.now().Sub(cur.loaded) < time.Duration(cur.soa.Expire)*time.Second/2 {
					return nil
				}
			}
		}

		rrs, err := m.transferFn(ctx, addr, m.timeout)
		if err != nil {
			lastErr = err
			metricTransfers.WithLabelValues("transfer_error").Inc()
			continue
		}
		if err := m.Load(rrs); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = errTransferShape
	}
	return lastErr
}

// Load installs a zone copy obtained by any means, subject to the same
// gate as a live transfer: full ZONEMD verification against the trust
// anchors, then an atomic swap. There is no unverified path into the
// active snapshot.
func (m *Manager) Load(rrs []dns.RR) error {
	if err := verifyZone(rrs, m.anchors()); err != nil {
		metricTransfers.WithLabelValues("verify_error").Inc()
		return err
	}
	snap, err := buildSnapshot(rrs, m.now())
	if err != nil {
		metricTransfers.WithLabelValues("build_error").Inc()
		return err
	}
	m.snap.Store(snap)
	metricTransfers.WithLabelValues("success").Inc()
	zlog.Info("Local root zone updated", "serial", snap.serial, "records", len(rrs))
	return nil
}

// jitter spreads d by ±10% so a fleet restarted together does not probe the
// same source in the same second forever.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	spread := int64(d / 10)
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1)) //nolint:gosec // schedule jitter, not key material.
}
