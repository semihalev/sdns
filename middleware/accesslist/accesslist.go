package accesslist

import (
	"context"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
	"github.com/yl2chen/cidranger"
)

// accessDenied counts queries dropped because the client IP isn't in
// the configured access list. Security-relevant — a spike indicates
// scanning or a misconfigured client trying repeatedly.
var accessDenied = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_accesslist_denied_total",
	Help: "Total DNS queries denied by the accesslist middleware",
})

// List type.
type List struct {
	ranger cidranger.Ranger
}

// New return accesslist.
func New(cfg *config.Config) *List {
	if len(cfg.AccessList) == 0 {
		cfg.AccessList = append(cfg.AccessList, "0.0.0.0/0")
		cfg.AccessList = append(cfg.AccessList, "::0/0")
	}

	a := new(List)
	a.ranger = cidranger.NewPCTrieRanger()
	for _, cidr := range cfg.AccessList {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			zlog.Error("Access list parse cidr failed", "error", err.Error())
			continue
		}

		_ = a.ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))

	}

	return a
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

	allowed, _ := a.ranger.Contains(ch.Writer.RemoteIP())

	if !allowed {
		accessDenied.Inc()
		// no reply to client
		ch.Cancel()
		return
	}

	ch.Next(ctx)
}

const name = "accesslist"
