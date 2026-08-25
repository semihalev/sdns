package localroot

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/zlog/v2"
)

// initialTransferDelay is how long the first transfer holds off after
// startup, before jitter widens it. Long enough for a cold resolver to
// prime, refresh its anchors and answer its first queries without sharing
// the link; short enough that the copy is serving within seconds.
const initialTransferDelay = 10 * time.Second

// DefaultSources are the root servers and ICANN hosts that publish the root
// zone over AXFR (RFC 8806 appendix A).
var DefaultSources = []string{
	"b.root-servers.net:53",
	"c.root-servers.net:53",
	"d.root-servers.net:53",
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

// CountApex counts a question at the root's own name answered from the copy.
func CountApex() { metricAnswers.WithLabelValues("apex").Inc() }

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
	// publish serializes the serial check and the swap in Load. The atomic
	// pointer keeps Active() lock-free on the read side, but the two steps
	// together are one decision: without this, two loads that both observe
	// an older serial can each pass the check and store in the opposite
	// order, quietly rolling the copy backwards — a sequence no race
	// detector reports, because every individual operation is legal.
	publish sync.Mutex

	// now/transferFn/probeFn are the test seams; production uses the
	// package functions and the wall clock.
	now        func() time.Time
	transferFn func(ctx context.Context, addr string, timeout time.Duration) ([]dns.RR, error)
	probeFn    func(ctx context.Context, addr string, timeout time.Duration) (uint32, error)
	// afterSerialCheck runs between the rollback check and the swap, nil in
	// production. The window it widens is a few instructions wide, which is
	// exactly why the ordering bug it guards against is invisible to both
	// the race detector and to volume testing: a test needs to hold the
	// section open to prove the section is exclusive.
	afterSerialCheck func()
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

	// The first transfer waits out the resolver's own cold start rather
	// than racing it. A couple of megabytes pulled over TCP while the
	// priming query, the trust-anchor refresh and the first client queries
	// are all in flight measurably slows them on a modest link — and the
	// copy is an optimization, so it should yield to the path it exists to
	// make faster. The jitter also keeps a fleet restarted together from
	// asking one transfer source for the zone in the same second.
	next := initialTransferDelay
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
		// probed carries what this source announced into the acceptance
		// check below, so the transfer is measured against the source's
		// own claim and not only against what is already installed.
		var (
			probed     uint32
			haveProbed bool
		)
		if cur != nil {
			serial, err := m.probeFn(ctx, addr, m.timeout)
			if err != nil {
				lastErr = err
				continue
			}
			probed, haveProbed = serial, true
			if serial != cur.serial && !serialNewer(cur.serial, serial) {
				// A source advertising an older zone is skipped whole:
				// nothing it transfers can be accepted (RFC 1982).
				lastErr = errSerialRollback
				continue
			}
			if serial == cur.serial {
				// Current: touch nothing. The copy's horizon — SOA expire
				// or earliest signature expiration, whichever is nearer —
				// is anchored at its transfer; a probe is not a transfer.
				// Transfer again once the copy has spent half that
				// horizon, so it keeps moving on a healthy source well
				// before it threatens.
				if m.now().Before(cur.loaded.Add(cur.expireAt.Sub(cur.loaded) / 2)) {
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
		// A source that announced a serial must deliver it. Failing over
		// to the next source is the point: the alternative is calling the
		// refresh a success and sleeping through a full interval on a copy
		// the source itself said was stale.
		if err := m.load(rrs, probed, haveProbed); err != nil {
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
// anchors, RFC 1982 serial acceptance against the live copy, then an
// atomic swap. There is no unverified path into the active snapshot, and
// no path backwards — a replayed older zone, however validly signed for
// its day, cannot displace a newer copy or restart its expire horizon.
func (m *Manager) Load(rrs []dns.RR) error {
	return m.load(rrs, 0, false)
}

// load is Load with the serial a probe advertised, when there was one.
// The transfer must deliver at least the zone the source announced: a
// source that advertises N+1 and then hands back N has not delivered the
// update, and accepting it would mark the refresh successful and wait a
// full refresh interval before asking anyone again.
func (m *Manager) load(rrs []dns.RR, expect uint32, expected bool) error {
	authUntil, err := verifyZone(rrs, m.anchors())
	if err != nil {
		metricTransfers.WithLabelValues("verify_error").Inc()
		return err
	}
	snap, err := buildSnapshot(rrs, m.now())
	if err != nil {
		metricTransfers.WithLabelValues("build_error").Inc()
		return err
	}
	// The digest is evidence only while the signature over it holds, so the
	// copy cannot outlive that signature however long its records run.
	snap.BoundTo(authUntil)
	if expected && snap.serial != expect && !serialNewer(expect, snap.serial) {
		metricTransfers.WithLabelValues("serial_behind_probe").Inc()
		return errSerialBehindProbe
	}

	m.publish.Lock()
	defer m.publish.Unlock()
	if cur := m.snap.Load(); cur != nil &&
		snap.serial != cur.serial && !serialNewer(cur.serial, snap.serial) {
		metricTransfers.WithLabelValues("serial_rollback").Inc()
		return errSerialRollback
	}
	if m.afterSerialCheck != nil {
		m.afterSerialCheck()
	}
	m.snap.Store(snap)
	metricTransfers.WithLabelValues("success").Inc()
	zlog.Info("Local root zone updated", "serial", snap.serial, "records", len(rrs))
	return nil
}

// serialNewer reports whether b is newer than a in RFC 1982 serial
// arithmetic (the SOA serial's number space).
func serialNewer(a, b uint32) bool {
	return (b > a && b-a < 1<<31) || (b < a && a-b > 1<<31)
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
