package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// A delegation is held for its lease and then dropped, and everything
// resolved under it inherits that lease: an answer can never outlive the
// delegation it came through. A delegation that is never renewed therefore
// takes every answer below it with it when its lease ends, those resolved a
// minute before included, and the cache empties zone by zone at the instant
// each busy delegation was first learned plus its lease.
//
// A delegation in use near the end of its lease is renewed instead: the
// walk that meets it schedules a refresh, which asks the parent again and
// replaces the entry with the referral's fresh lease. What is resolved under
// it afterwards inherits the new one. The refresh never extends anything on
// its own authority: the new lease is a fresh referral's, from the parent,
// inheriting the parent's own cut as every referral does.

var resolverRefreshes = metric.NewCounterVec(nil, prometheus.CounterOpts{
	Name: "dns_resolver_refresh_total",
	Help: "Delegations and nameserver glue refreshed ahead of their end, by type and result",
}, []string{"type", "result"})

// refreshCounters are one type's results: renewed, the refresh stored a
// new entry; failed, it ran and stored nothing; shed, the lane was full.
type refreshCounters struct{ renewed, failed, shed *metric.Counter }

func newRefreshCounters(kind string) refreshCounters {
	return refreshCounters{
		renewed: resolverRefreshes.Register(kind, "renewed"),
		failed:  resolverRefreshes.Register(kind, "failed"),
		shed:    resolverRefreshes.Register(kind, "shed"),
	}
}

var (
	delegationRefreshes = newRefreshCounters("delegation")
	glueV4Refreshes     = newRefreshCounters("glue_v4")
	glueV6Refreshes     = newRefreshCounters("glue_v6")
)

// errRefreshDue is how a refresh walk's cache search reads a delegation due
// for renewal: as absent.
var errRefreshDue = errors.New("delegation due for refresh")

// delegationRefreshShare is the part of a delegation's granted lease, its
// last 1/share, in which using it schedules a refresh. Atomic only so a
// test can widen it while background walks read it.
var delegationRefreshShare = func() *atomic.Int64 {
	var v atomic.Int64
	v.Store(10)
	return &v
}()

// refreshWindow is the last part of granted in which a refresh is due.
func refreshWindow(granted time.Duration) time.Duration {
	return granted / time.Duration(delegationRefreshShare.Load())
}

// refreshDue reports whether d, used now, is in the last part of its lease.
func refreshDue(d *authority.Delegation, now time.Time) bool {
	granted := d.Granted()
	if granted <= 0 {
		return false
	}
	left, bounded := d.Lease.Remaining(now)
	return bounded && left > 0 && left <= refreshWindow(granted)
}

// scheduleDelegationRefresh offers a refresh of the delegation for zone to
// the refresh lane, once per delegation: the claim is held until the
// refresh is over. A full lane sheds it; the delegation then runs out as
// it would have, and the next use near its end offers it again.
func (r *Resolver) scheduleDelegationRefresh(zone string, cd bool, d *authority.Delegation) {
	if !d.ClaimRefresh() {
		return
	}
	job := nsEnrichJob{
		base: middleware.WithBestEffortRecursionWork(context.Background()),
		run: func(ctx context.Context) {
			defer d.ReleaseRefresh()
			if r.refreshDelegation(ctx, zone, cd, d) {
				delegationRefreshes.renewed.Inc()
			} else {
				delegationRefreshes.failed.Inc()
			}
		},
	}
	if !enqueueEnrich(r.refreshLane, job) {
		d.ReleaseRefresh()
		delegationRefreshes.shed.Inc()
	}
}

// glueRefreshDue reports whether glue e, read now, is in the last part of
// the lifetime it was stored with.
func glueRefreshDue(e *glueEntry, now time.Time) bool {
	if e.granted <= 0 {
		return false
	}
	left := time.Duration(e.expiresAt - now.UnixNano())
	return left > 0 && left <= refreshWindow(e.granted)
}

// maybeRefreshGlue offers a refresh of host's addresses of type qtype, held
// in c, when they are near their end: the glue a delegation is built from
// is renewed while it is in use, the way the delegation itself is, so a
// delegation rebuilt late in the glue's life does not find it gone.
func (r *Resolver) maybeRefreshGlue(c *cache.Cache[*glueEntry], host string, qtype uint16, cd bool) {
	if c == nil {
		return
	}
	e, ok := c.Get(cache.Key(dns.Question{Name: host, Qtype: qtype, Qclass: dns.ClassINET}))
	if !ok || !glueRefreshDue(e, time.Now()) || !e.mark.CompareAndSwapFlag(false, true) {
		return
	}
	counters := glueV4Refreshes
	if qtype == dns.TypeAAAA {
		counters = glueV6Refreshes
	}
	job := nsEnrichJob{
		base: middleware.WithBestEffortRecursionWork(context.Background()),
		run: func(ctx context.Context) {
			defer e.mark.SetFlag(false)
			if r.refreshGlue(ctx, c, e, host, qtype, cd) {
				counters.renewed.Inc()
			} else {
				counters.failed.Inc()
			}
		},
	}
	if !enqueueEnrich(r.refreshLane, job) {
		e.mark.SetFlag(false)
		counters.shed.Inc()
	}
}

// refreshGlue resolves host's addresses again and stores them in c in place
// of e, and reports whether it did. The lookup skips the answer cache, which
// would hand back the very addresses being renewed, and keeps the rest of
// the pipeline. A failed lookup changes nothing, and neither does one that
// finishes after e was replaced or removed: the newer glue stands.
func (r *Resolver) refreshGlue(ctx context.Context, c *cache.Cache[*glueEntry], e *glueEntry, host string, qtype uint16, cd bool) bool {
	q := r.refreshQueryer.Load()
	if q == nil {
		if q = r.queryer.Load(); q == nil {
			return false
		}
	}
	ctx = context.WithValue(ctx, contextKeyNSL, struct{}{})
	req := new(dns.Msg)
	req.SetQuestion(host, qtype)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)
	req.CheckingDisabled = cd

	resp, err := (*q).Query(ctx, req)
	if err != nil {
		return false
	}
	addrs, ttl, ok := searchAddrs(resp)
	if !ok {
		return false
	}
	renewed, until := newGlueEntry(nsAddrs{addrs: addrs, ttl: ttl})
	return c.CompareAndSwapUntil(cache.Key(dns.Question{Name: host, Qtype: qtype, Qclass: dns.ClassINET}), e, renewed, until)
}

// refreshTarget is the entry a refresh walk set out to renew, and whether
// it was.
type refreshTarget struct {
	key     uint64
	from    *authority.Delegation
	renewed atomic.Bool
}

// errRefreshSuperseded ends a refresh walk whose entry was removed or
// replaced while it ran: there is nothing left for it to renew.
var errRefreshSuperseded = errors.New("delegation refresh superseded")

// errRefreshDone ends a refresh walk once its entry is renewed.
var errRefreshDone = errors.New("delegation refresh done")

// refreshDelegation resolves zone's NS set in refresh mode to renew d, and
// reports whether it did: the walk treats every delegation on its path that
// is due for renewal as absent, so it starts at the deepest one that is not,
// asks each parent below it again, and renews the due entries from the
// referrals it receives, the shallowest first, so each inherits its parent's
// renewed lease and not the old one. The walk asks iteratively, as every
// walk does once the handler has cleared RD: a parent that refuses
// recursion answers it like any other.
func (r *Resolver) refreshDelegation(ctx context.Context, zone string, cd bool, d *authority.Delegation) bool {
	req := new(dns.Msg)
	req.SetQuestion(zone, dns.TypeNS)
	req.RecursionDesired = false
	req.CheckingDisabled = cd
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	target := &refreshTarget{
		key:  cache.Key(dns.Question{Name: zone, Qtype: dns.TypeNS, Qclass: dns.ClassINET}, cd),
		from: d,
	}
	// A job can wait in the lane; one whose entry is gone or replaced
	// by then has nothing to ask the parent for.
	if cur, err := r.delegations.Get(target.key); err != nil || cur != d {
		return false
	}
	if _, err := r.resolveRooted(ctx, req, r.cfg.Maxdepth, target); err != nil && !errors.Is(err, errRefreshDone) && debugLogEnabled() {
		zlog.Debug("Delegation refresh failed", "zone", zone, "cd", cd, "error", err.Error())
	}
	return target.renewed.Load()
}
