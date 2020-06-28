package recovery

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// Recovery dummy type
type Recovery struct{}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return recovery
func New(cfg *config.Config) *Recovery {
	return &Recovery{}
}

// Name return middleware name
func (r *Recovery) Name() string { return name }

// ServeDNS implements the Handle interface.
func (r *Recovery) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	defer func() {
		if r := recover(); r != nil {
			ch.Writer.WriteMsg(dnsutil.HandleFailed(ch.Request, dns.RcodeServerFailure, false))

			log.Error("Recovered in ServeDNS", "recover", r)

			os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
		}
	}()

	ch.Next(ctx)
}

const name = "recovery"
