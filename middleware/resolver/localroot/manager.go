package localroot

import (
	"context"
	"crypto/sha256"
	"math/rand/v2"
	"sort"
	"strings"
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

// serving is the manager driving the refresh loop, which is the one the
// gauges below describe. Set when Run starts; nil in a process where the
// feature is off, and in tests, which drive a manager directly.
var serving atomic.Pointer[Manager]

// observed reports what the live copy looks like at scrape time, or -1 when
// there is nothing to describe. Reading at scrape rather than writing on
// refresh is what keeps the age honest: the refresh loop wakes on the zone's
// SOA schedule, so a pushed value would sit frozen for up to a refresh
// interval and read as though the copy had just arrived.
func observed(pick func(age, serial float64) float64) float64 {
	m := serving.Load()
	if m == nil {
		return -1
	}
	return pick(m.observe())
}

var (
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "dns_localroot_copy_age_seconds",
		Help: "Age of the active local root zone copy; -1 when none is active",
	}, func() float64 {
		return observed(func(age, _ float64) float64 { return age })
	})
	_ = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "dns_localroot_serial",
		Help: "SOA serial of the active local root zone copy; -1 when none is active",
	}, func() float64 {
		return observed(func(_, serial float64) float64 { return serial })
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

// CountFallback counts a root consult the copy did not answer, so the walk
// went to the real root servers: no verified copy was active, or the copy
// held no proof of the answer being asked for. Every consult is either an
// answer of one kind or a fallback, so the kinds sum to the consults.
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
	// anchorNow caches the last observation of the live trust anchor set,
	// so Active can compare against it without rebuilding the DS set on
	// every root consult.
	anchorNow atomic.Pointer[anchorState]

	// sourceOffset is where the next refresh starts in the source list. It
	// begins at a random point so a fleet does not converge on one host, and
	// advances per cycle so a single resolver spreads its own transfers too.
	// Tests set it to make the walk deterministic.
	sourceOffset atomic.Uint64
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
	// Blank entries are dropped before the emptiness test, so a config that
	// sets the list to [""] falls back to the built-in sources instead of
	// leaving one unusable address and silently disabling the feature.
	usable := make([]string, 0, len(sources))
	for _, addr := range sources {
		if addr = strings.TrimSpace(addr); addr != "" {
			usable = append(usable, addr)
		}
	}
	sources = usable
	if len(sources) == 0 {
		sources = DefaultSources
	}
	m := &Manager{
		sources:    sources,
		anchors:    anchors,
		timeout:    30 * time.Second,
		now:        time.Now,
		transferFn: axfr,
		probeFn:    probeSerial,
	}
	m.sourceOffset.Store(rand.Uint64()) //nolint:gosec // load spreading, not key material.
	return m
}

// anchorRecheckInterval bounds how stale Active's view of the trust anchors
// may be. Rebuilding the anchor DS set costs a lock and a hash per key, and
// Active runs on every root consult, so the answer is reused for this long —
// a second of staleness against an anchor change measured in years.
const anchorRecheckInterval = time.Second

// anchorState is one observation of the live trust anchor set.
type anchorState struct {
	fp        [sha256.Size]byte
	usable    bool
	checkedAt time.Time
}

// Active returns the verified snapshot to serve from, or nil when there is
// none — never transferred, the copy has outlived its horizon, or the trust
// anchors that verified it are no longer the resolver's.
func (m *Manager) Active() *Snapshot {
	s := m.snap.Load()
	if s == nil || s.Expired(m.now()) {
		return nil
	}
	if !m.anchorsStillHold(s) {
		return nil
	}
	return s
}

// anchorsStillHold reports whether the trust anchors that verified this copy
// are still the ones the resolver holds.
//
// Expiry alone is not enough to decide a copy may still be served. RFC 8806
// §2 requires the copy to be validated with an up-to-date root KSK, and RFC
// 8976 §6.4 notes that a ZONEMD digest is only as good as the DNSSEC chain
// behind it — once the anchors are gone, nothing here can be re-derived. So
// an anchor set that AutoTA has emptied fail-closed, or one whose keys have
// been replaced or revoked, withdraws the copy immediately rather than
// letting days of horizon run on evidence that no longer exists. The walk
// falls back to the real roots and the next refresh re-verifies the zone
// under whatever anchors are current by then.
func (m *Manager) anchorsStillHold(s *Snapshot) bool {
	now := m.now()
	cur := m.anchorNow.Load()
	if cur == nil || now.Sub(cur.checkedAt) >= anchorRecheckInterval {
		fp, usable := anchorFingerprint(m.anchors())
		cur = &anchorState{fp: fp, usable: usable, checkedAt: now}
		m.anchorNow.Store(cur)
	}
	return cur.usable && cur.fp == s.anchorFP
}

// anchorFingerprint identifies a trust anchor set independently of the order
// its records arrive in. An empty set is not usable: it cannot verify
// anything, so it cannot keep a copy alive either.
func anchorFingerprint(anchors []dns.RR) (fp [sha256.Size]byte, usable bool) {
	if len(anchors) == 0 {
		return fp, false
	}
	presentations := make([]string, 0, len(anchors))
	for _, rr := range anchors {
		if rr == nil {
			continue
		}
		// The TTL is not part of a trust anchor's identity — the same key
		// material re-read with a different lifetime is the same anchor. It
		// is zeroed rather than left in, because a fingerprint that moved
		// with it would withdraw a sound copy and send the walk to the real
		// roots over nothing.
		identity := dns.Copy(rr)
		identity.Header().Ttl = 0
		presentations = append(presentations, strings.ToLower(identity.String()))
	}
	if len(presentations) == 0 {
		return fp, false
	}
	sort.Strings(presentations)

	h := sha256.New()
	for _, p := range presentations {
		_, _ = h.Write([]byte(p))
		_, _ = h.Write([]byte{0})
	}
	h.Sum(fp[:0])
	return fp, true
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

	// The manager that owns the refresh lifecycle is the one the gauges
	// describe; they read it at scrape time.
	serving.Store(m)

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

	}
}

// observe reports what the gauges should say about the copy right now: its
// age in seconds and its SOA serial, or -1 for both when no copy is active.
// The two travel together — an age without a serial cannot tell a fleet
// whether its nodes converged on the same zone, and a serial without an age
// cannot tell whether the copy behind it is still moving.
func (m *Manager) observe() (age, serial float64) {
	s := m.Active()
	if s == nil {
		return -1, -1
	}
	return m.now().Sub(s.Loaded()).Seconds(), float64(s.serial)
}

// refreshOnce probes for a serial change and transfers when one is seen (or
// when no copy exists yet). The probe's source is the transfer's source, so a
// host that cannot answer is skipped whole.
//
// Each cycle starts at a different source. Walking the list from the top
// every time would send every healthy resolver in a fleet to the same first
// host for every transfer it ever makes, which is the opposite of what a
// list of eight equivalent sources is for.
func (m *Manager) refreshOnce(ctx context.Context) error {
	// Without anchors nothing this cycle transfers can be verified, and the
	// refusal would come only after the zone was on the wire. Checking first
	// costs one comparison and saves pulling a few megabytes from every
	// source, every retry interval, for as long as the anchors stay empty —
	// which is a state the resolver can hold indefinitely if the trust
	// anchors fail closed.
	if len(m.anchors()) == 0 {
		metricTransfers.WithLabelValues("no_anchors").Inc()
		return errNoAnchors
	}

	cur := m.snap.Load()

	var lastErr error
	// The modulo happens in uint64: converting the counter to int first
	// turns any value past MaxInt64 negative, and a negative remainder
	// indexes backwards out of the slice.
	start := int((m.sourceOffset.Add(1) - 1) % uint64(len(m.sources))) //nolint:gosec // the modulo bounds this below len(m.sources), an int.
	for i := range m.sources {
		addr := m.sources[(start+i)%len(m.sources)]
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
	// One normalization stage, ahead of every reader: see normalizeZone.
	rrs = normalizeZone(rrs)

	// One reading of the anchors for both the verification and the
	// fingerprint stamped on the copy: taking them twice could verify
	// against one set and record another.
	anchors := m.anchors()
	authUntil, err := verifyZone(rrs, anchors)
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
	// verifyZone refuses an empty anchor set, so usable is true here; the
	// fingerprint is what Active later compares the live anchors against.
	snap.anchorFP, _ = anchorFingerprint(anchors)
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
