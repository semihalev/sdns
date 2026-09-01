package rpz

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/internal/zonetransfer"
	"github.com/semihalev/zlog/v2"
)

// A policy feed can legitimately run to millions of records; these bounds
// exist for the stream that is not a feed at all.
var feedTransferLimits = zonetransfer.Limits{
	MaxRecords: 16 << 20,
	MaxBytes:   1 << 30,
}

const (
	// axfrTimeout bounds one probe or transfer attempt.
	axfrTimeout = 2 * time.Minute
	// axfrInitialRetry paces attempts until the first copy lands, before
	// that there is no SOA to take a retry interval from.
	axfrInitialRetry = time.Minute
)

// axfrFeed keeps one AXFR-sourced zone current: probe on the SOA refresh
// interval, transfer on serial change, retry on the SOA retry interval,
// and withdraw the rules past SOA expire, a feed that cannot be
// refreshed must not keep enforcing what it said long ago. The loop's
// schedule is deliberately its own (see internal/zonetransfer's package
// note): it is welded to exactly this withdrawal semantic.
type axfrFeed struct {
	r    *RPZ
	idx  int
	name string
	// origin is the configured apex; source the primary.
	origin string
	source string
	policy rpz.Override
	cname  string
	tsig   *rpz.TSIGKey

	// now is the test seam for the expire clock; timeout bounds one
	// probe or transfer attempt (a test shrinks it).
	now     func() time.Time
	timeout time.Duration

	// serial/loaded describe the installed copy; zero serial means none.
	serial    uint32
	haveCopy  bool
	loaded    time.Time
	refresh   time.Duration
	retry     time.Duration
	expire    time.Duration
	withdrawn bool
}

func newAXFRFeed(r *RPZ, idx int, zc config.RPZZone) *axfrFeed {
	key, _ := rpz.ParseTSIGKey(zc.TsigKey) // the config gate refused a bad one
	policy, _ := rpz.ParseOverride(zc.Policy)
	target := ""
	if zc.Cname != "" {
		target = dns.CanonicalName(zc.Cname)
	}
	return &axfrFeed{
		r:       r,
		idx:     idx,
		name:    zc.Name,
		origin:  dns.CanonicalName(zc.Origin),
		source:  zc.Source,
		policy:  policy,
		cname:   target,
		tsig:    key,
		now:     time.Now,
		timeout: axfrTimeout,
	}
}

// run is the feed's lifecycle; it holds the schedule and never returns.
func (f *axfrFeed) run(ctx context.Context) {
	var next time.Duration
	// The first attempt goes out immediately: an empty zone filters
	// nothing, and every second before the first copy is policy the
	// operator configured and is not getting.
	timer := time.NewTimer(0)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		next = f.cycle(ctx)
		timer.Reset(next)
	}
}

// cycle is one wake of the feed: withdrawal first, then the refresh.
// The order is the expire contract, a copy past its horizon stops
// serving before the refresh attempt starts, not up to a transfer
// timeout later; the next successful transfer rebuilds it.
func (f *axfrFeed) cycle(ctx context.Context) time.Duration {
	f.maybeWithdraw()
	afterFailure := false
	if err := f.refreshOnce(ctx); err != nil {
		afterFailure = true
		f.maybeWithdraw() // the attempt itself may have crossed the horizon
		zlog.Warn("RPZ feed refresh failed", "zone", f.name, "source", f.source, "error", err.Error())
	}
	return f.sleepFor(afterFailure)
}

// Bounds on the schedule the feed's SOA dictates: a zero or tiny refresh
// must not become a hot probe loop, and a wake must land at the expire
// boundary so a copy is withdrawn when its time comes rather than a full
// retry interval later.
const minFeedInterval = 30 * time.Second

// nextWake is the interval to the next cycle: SOA retry after a failure,
// SOA refresh after success, floored so a degenerate SOA cannot spin.
func (f *axfrFeed) nextWake(afterFailure bool) time.Duration {
	next := f.refresh
	if afterFailure {
		next = f.retry
	}
	if !f.haveCopy || next <= 0 {
		next = axfrInitialRetry
	}
	if next < minFeedInterval {
		next = minFeedInterval
	}
	return next
}

// expireCap is the exact time left before the installed copy must be
// withdrawn, no grace, no floor: the refresh clamp built on it has to
// die at the horizon itself, or a probe succeeding just past it would
// renew a copy that had already outlived its trust. ok is false when
// nothing is aging toward a horizon.
func (f *axfrFeed) expireCap() (time.Duration, bool) {
	if !f.haveCopy || f.withdrawn {
		return 0, false
	}
	return f.loaded.Add(f.expire).Sub(f.now()), true
}

// sleepFor is the actual sleep: the SOA-paced interval jittered so a
// fleet does not probe in lockstep, then capped at the copy's remaining
// expire. The cap is applied after the jitter and never jittered itself,
// the expire boundary is a deadline, and a wake that must withdraw cannot
// be allowed to drift past it. Nor is there anything to add to it: a Go
// timer never fires early, and the withdrawal check treats the exact
// horizon as expired, so the wake lands at the boundary and withdraws.
func (f *axfrFeed) sleepFor(afterFailure bool) time.Duration {
	sleep := zonetransfer.Jitter(f.nextWake(afterFailure))
	if remaining, ok := f.expireCap(); ok && remaining < sleep {
		sleep = remaining
	}
	return sleep
}

// refreshOnce probes for a serial change and transfers when one is seen
// (or when no copy exists yet). A source advertising an older serial is
// refused whole: nothing it transfers can be accepted (RFC 1982).
func (f *axfrFeed) refreshOnce(ctx context.Context) error {
	timeout := f.timeout
	// While a live copy is aging, the attempt itself is bounded by the
	// copy's horizon: an attempt still running at expire is cancelled so
	// its failure path withdraws at the boundary, otherwise a cycle
	// starting just inside the horizon would keep stale rules serving
	// for a full transfer timeout past it, and a probe succeeding late
	// would renew a copy that had already outlived its trust. Withdrawn
	// (or first-copy) attempts get the full budget: there is nothing
	// left to protect, only a zone to rebuild.
	if remaining, ok := f.expireCap(); ok && remaining < timeout {
		timeout = remaining
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if f.haveCopy {
		serial, err := zonetransfer.ProbeSerial(ctx, f.source, f.origin, f.timeout)
		switch {
		case err != nil && f.tsig == nil:
			return err
		case err != nil:
			// The probe travels unsigned; a TSIG provider may gate even
			// the SOA question. The signed transfer below then serves as
			// the probe, dearer, but the alternative is a feed that can
			// never refresh.
		case serial == f.serial && !f.withdrawn:
			f.loaded = f.now() // a healthy probe restarts the expire clock
			return nil
		case serial == f.serial:
			// Withdrawn: the store holds an empty zone, so an equal
			// serial is not "nothing to do", the copy must be rebuilt.
			// Fall through to the transfer.
		case !zonetransfer.SerialNewer(f.serial, serial):
			// A source advertising an older zone is refused whole:
			// nothing it transfers can be accepted (RFC 1982).
			return fmt.Errorf("source advertises serial %d behind installed %d", serial, f.serial)
		}
	}

	rrs, err := f.transfer(ctx)
	if err != nil {
		return err
	}
	rrs = zonetransfer.NormalizeZone(rrs)
	z, err := rpz.CompileRecords(f.name, rrs, f.policy, f.cname)
	if err != nil {
		return err
	}
	// The gate's zero-rule semantic, exactly as the file reload applies
	// it: a transfer that compiles nothing is a broken push, and the
	// previous rules keep serving.
	if z.Rules == 0 {
		return fmt.Errorf("transfer compiled no rules (skipped: %v)", z.Skipped)
	}
	// An expire of zero would disable the withdrawal horizon outright:
	// the source is declaring its copy trustworthy for no time at all,
	// and a feed built on that would enforce stale rules forever the day
	// the source disappears. That is a broken SOA, not a schedule.
	if z.SOA.Expire == 0 {
		return fmt.Errorf("transfer SOA declares expire 0; a copy that can never be trusted cannot be installed")
	}
	if f.haveCopy && z.SOA.Serial != f.serial && !zonetransfer.SerialNewer(f.serial, z.SOA.Serial) {
		return fmt.Errorf("transfer delivered serial %d behind installed %d", z.SOA.Serial, f.serial)
	}

	f.install(z)
	return nil
}

// install swaps the compiled zone into the store and adopts its schedule.
func (f *axfrFeed) install(z *rpz.Zone) {
	f.r.swapZone(f.idx, z)

	f.serial = z.SOA.Serial
	f.haveCopy = true
	f.withdrawn = false
	f.loaded = f.now()
	f.refresh = time.Duration(z.SOA.Refresh) * time.Second
	f.retry = time.Duration(z.SOA.Retry) * time.Second
	f.expire = time.Duration(z.SOA.Expire) * time.Second

	publishZoneMetrics(z)
	zoneSerial.WithLabelValues(f.name).Set(float64(z.SOA.Serial))
	zlog.Info("RPZ feed transferred", "zone", f.name, "serial", z.SOA.Serial, "rules", z.Rules, "skipped", len(z.Skipped))
}

// maybeWithdraw retires the rules of a copy past its SOA expire: the feed
// said how long it may be trusted without contact, and past that the
// policy fails open on this zone rather than enforcing stale rules.
func (f *axfrFeed) maybeWithdraw() {
	if !f.haveCopy || f.withdrawn {
		return
	}
	if f.now().Before(f.loaded.Add(f.expire)) {
		return
	}
	f.withdrawn = true
	f.r.swapZone(f.idx, &rpz.Zone{Name: f.name, Policy: f.policy, CNAMETarget: f.cname})
	zoneSerial.WithLabelValues(f.name).Set(-1)
	reloadErrors.WithLabelValues(f.name).Inc()
	zlog.Warn("RPZ feed expired and its rules are withdrawn; resolution continues unfiltered by this zone",
		"zone", f.name, "serial", f.serial, "expire", f.expire.String())
}

func (f *axfrFeed) transfer(ctx context.Context) ([]dns.RR, error) {
	if f.tsig == nil {
		return zonetransfer.AXFR(ctx, f.source, f.origin, f.timeout, feedTransferLimits)
	}
	return f.transferTSIG(ctx)
}

// transferTSIG pulls the zone through miekg's dns.Transfer, which owns
// the RFC 8945 envelope-MAC chain, the one part of a signed transfer
// that must not be re-implemented here, and then applies the same shape
// and bound discipline the strict core applies: SOA-bracketed, terminator
// duplicating the opener, caller-owned limits, closing SOA dropped.
func (f *axfrFeed) transferTSIG(ctx context.Context) ([]dns.RR, error) {
	req := new(dns.Msg)
	req.SetAxfr(f.origin)
	req.SetTsig(f.tsig.Name, f.tsig.Algorithm, 300, time.Now().Unix())

	// The connection is dialed here, not left to dns.Transfer: its read
	// deadline restarts on every envelope, so a source dripping one
	// envelope per interval could hold an attempt open indefinitely,
	// past the attempt budget, past the caller's cancellation, and past
	// the expire boundary the feed loop must be awake for. A deadline
	// cannot bound the whole attempt (the per-envelope reset overwrites
	// whatever is set on the socket); closing the socket can, a closed
	// connection wakes the blocked read and refuses every one after it.
	// The watchdog fires at the attempt budget, the AfterFunc on the
	// caller's cancellation.
	d := net.Dialer{Timeout: f.timeout}
	conn, err := d.DialContext(ctx, "tcp", f.source)
	if err != nil {
		return nil, err
	}
	// Deferred in this order so the drain runs after the close: closing
	// the socket fails the producer's next read, but a producer already
	// parked on the unbuffered envelope send needs a reader to get there.
	// Without the drain, every early return below, shape, limit, even
	// the terminator, can strand the transfer goroutine for good.
	var env chan *dns.Envelope
	defer func() {
		if env == nil {
			return
		}
		for range env { //nolint:revive // drained for the side effect
		}
	}()
	defer func() { _ = conn.Close() }()
	budget := f.timeout
	if ctxDeadline, ok := ctx.Deadline(); ok {
		if until := time.Until(ctxDeadline); until < budget {
			budget = until
		}
	}
	watchdog := time.AfterFunc(budget, func() { _ = conn.Close() })
	defer watchdog.Stop()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	secrets := map[string]string{f.tsig.Name: f.tsig.Secret}
	tr := &dns.Transfer{
		Conn:       &dns.Conn{Conn: conn, TsigSecret: secrets},
		TsigSecret: secrets,
	}

	env, err = tr.In(req, f.source)
	if err != nil {
		return nil, err // In fails before spawning a producer; env stays nil
	}

	var (
		rrs      []dns.RR
		sawFirst bool
		total    int
	)
	for e := range env {
		if e.Error != nil {
			return nil, e.Error
		}
		for _, rr := range e.RR {
			isApexSOA := rr.Header().Rrtype == dns.TypeSOA &&
				dns.CanonicalName(rr.Header().Name) == f.origin
			if !sawFirst {
				if !isApexSOA {
					return nil, zonetransfer.ErrShape
				}
				sawFirst = true
				rrs = append(rrs, rr)
				continue
			}
			if isApexSOA {
				if !dns.IsDuplicate(rrs[0], rr) {
					return nil, zonetransfer.ErrShape
				}
				return rrs, nil
			}
			total += dns.Len(rr)
			if len(rrs) >= feedTransferLimits.MaxRecords || total > feedTransferLimits.MaxBytes {
				return nil, zonetransfer.ErrLimit
			}
			rrs = append(rrs, rr)
		}
	}
	if !sawFirst {
		return nil, zonetransfer.ErrShape
	}
	// The envelope stream ended without the closing SOA.
	return nil, zonetransfer.ErrShape
}
