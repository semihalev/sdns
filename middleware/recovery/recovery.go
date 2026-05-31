package recovery

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// panics counts caught panics in downstream middleware. A non-zero
// rate is a critical signal — every panic is a bug that the recovery
// middleware turned into a SERVFAIL for the client. Alert on rate(),
// not on absolute value.
var panics = metric.NewCounter(nil, prometheus.CounterOpts{
	Name: "dns_recovery_panics_total",
	Help: "Total panics caught by the recovery middleware",
})

// Recovery dummy type.
type Recovery struct{}

// New return recovery.
func New(cfg *config.Config) *Recovery {
	return &Recovery{}
}

// (*Recovery).Name name return middleware name.
func (r *Recovery) Name() string { return name }

// (*Recovery).ServeDNS serveDNS implements the Handle interface.
func (r *Recovery) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	defer func() {
		if r := recover(); r != nil {
			panics.Inc()
			ch.CancelWithRcode(dns.RcodeServerFailure, false)

			zlog.Error("Recovered in ServeDNS", "recover", r)

			_, _ = fmt.Fprintf(os.Stderr, "panic: %v\n\n", r)
			debug.PrintStack()
		}
	}()

	ch.Next(ctx)
}

const name = "recovery"
