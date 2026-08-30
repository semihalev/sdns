package rpz

import (
	"context"
	"fmt"
	"github.com/semihalev/sdns/config"
	"time"

	"github.com/miekg/dns"
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
	// axfrInitialRetry paces attempts until the first copy lands — before
	// that there is no SOA to take a retry interval from.
	axfrInitialRetry = time.Minute
)

// axfrFeed keeps one AXFR-sourced zone current: probe on the SOA refresh
// interval, transfer on serial change, retry on the SOA retry interval,
// and withdraw the rules past SOA expire — a feed that cannot be
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

	// now is the test seam for the expire clock.
	now func() time.Time

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
		r:      r,
		idx:    idx,
		name:   zc.Name,
		origin: dns.CanonicalName(zc.Origin),
		source: zc.Source,
		policy: policy,
		cname:  target,
		tsig:   key,
		now:    time.Now,
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

		if err := f.refreshOnce(ctx); err != nil {
			f.maybeWithdraw()
			next = f.retryInterval()
			zlog.Warn("RPZ feed refresh failed", "zone", f.name, "source", f.source, "error", err.Error())
		} else {
			next = f.refresh
		}
		timer.Reset(zonetransfer.Jitter(next))
	}
}

func (f *axfrFeed) retryInterval() time.Duration {
	if f.haveCopy && f.retry > 0 {
		return f.retry
	}
	return axfrInitialRetry
}

// refreshOnce probes for a serial change and transfers when one is seen
// (or when no copy exists yet). A source advertising an older serial is
// refused whole: nothing it transfers can be accepted (RFC 1982).
func (f *axfrFeed) refreshOnce(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, axfrTimeout)
	defer cancel()

	if f.haveCopy {
		serial, err := zonetransfer.ProbeSerial(ctx, f.source, f.origin, axfrTimeout)
		switch {
		case err != nil && f.tsig == nil:
			return err
		case err != nil:
			// The probe travels unsigned; a TSIG provider may gate even
			// the SOA question. The signed transfer below then serves as
			// the probe — dearer, but the alternative is a feed that can
			// never refresh.
		case serial == f.serial:
			f.loaded = f.now() // a healthy probe restarts the expire clock
			f.withdrawn = false
			return nil
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
	if !f.haveCopy || f.withdrawn || f.expire <= 0 {
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
		return zonetransfer.AXFR(ctx, f.source, f.origin, axfrTimeout, feedTransferLimits)
	}
	return f.transferTSIG(ctx)
}

// transferTSIG pulls the zone through miekg's dns.Transfer, which owns
// the RFC 8945 envelope-MAC chain — the one part of a signed transfer
// that must not be re-implemented here — and then applies the same shape
// and bound discipline the strict core applies: SOA-bracketed, terminator
// duplicating the opener, caller-owned limits, closing SOA dropped.
func (f *axfrFeed) transferTSIG(ctx context.Context) ([]dns.RR, error) {
	req := new(dns.Msg)
	req.SetAxfr(f.origin)
	req.SetTsig(f.tsig.Name, f.tsig.Algorithm, 300, time.Now().Unix())

	tr := &dns.Transfer{
		TsigSecret:  map[string]string{f.tsig.Name: f.tsig.Secret},
		DialTimeout: axfrTimeout,
		ReadTimeout: axfrTimeout,
	}

	env, err := tr.In(req, f.source)
	if err != nil {
		return nil, err
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
