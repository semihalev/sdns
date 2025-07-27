package recovery

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

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
			ch.CancelWithRcode(dns.RcodeServerFailure, false)

			zlog.Error("Recovered in ServeDNS", "recover", r)

			_, _ = os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
		}
	}()

	ch.Next(ctx)
}

const name = "recovery"
