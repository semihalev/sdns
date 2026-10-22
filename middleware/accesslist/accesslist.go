package accesslist

import (
	"context"
	"fmt"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/ipset"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// accessDenied counts queries dropped because the client IP isn't in
// the configured access list. Security-relevant, a spike indicates
// scanning or a misconfigured client trying repeatedly.
var accessDenied = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_accesslist_denied_total",
	Help: "Total DNS queries denied by the accesslist middleware",
})

// List type.
type List struct {
	// allowed is swapped whole by a reload.
	allowed atomic.Pointer[ipset.Set]
}

// New return accesslist.
func New(cfg *config.Config) *List {
	if len(cfg.AccessList) == 0 {
		cfg.AccessList = append(cfg.AccessList, "0.0.0.0/0")
		cfg.AccessList = append(cfg.AccessList, "::0/0")
	}

	a := new(List)
	set, bad := ipset.New(cfg.AccessList)
	for _, entry := range bad {
		zlog.Error("Access list parse cidr failed", "cidr", entry.CIDR, "error", entry.Err.Error())
	}
	a.allowed.Store(set)

	return a
}

// ReloadKeys implements middleware.Reloader.
func (a *List) ReloadKeys() []string { return []string{"accesslist"} }

// PrepareReload implements middleware.Reloader: the new list is compiled
// here and put in use on commit.
func (a *List) PrepareReload(cfg *config.Config) (func(), error) {
	entries := cfg.AccessList
	if len(entries) == 0 {
		entries = []string{"0.0.0.0/0", "::0/0"}
	}
	set, bad := ipset.New(entries)
	if len(bad) > 0 {
		return nil, fmt.Errorf("accesslist entry %q: %v", bad[0].CIDR, bad[0].Err)
	}
	return func() { a.allowed.Store(set) }, nil
}

// (*List).Name name return middleware name.
func (a *List) Name() string { return name }

// (*List).ClientOnly marks access-list enforcement as
// client-traffic-only; middleware.Setup excludes it from internal
// sub-pipelines so an internal sub-query isn't denied by a
// source-IP rule that doesn't apply to internal traffic.
func (a *List) ClientOnly() bool { return true }

// (*List).ServeDNS serveDNS implements the Handle interface.
func (a *List) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if ch.Writer.Internal() {
		ch.Next(ctx)
		return
	}

	// This runs before the cache, so it runs on every query the server
	// answers: the lookup is a binary search over compiled ranges and
	// allocates nothing, which is why the open default no longer needs a
	// flag to skip it.
	if !a.allowed.Load().ContainsIP(ch.Writer.RemoteIP()) {
		accessDenied.Inc()
		// no reply to client
		ch.Cancel()
		return
	}

	ch.Next(ctx)
}

const name = "accesslist"
