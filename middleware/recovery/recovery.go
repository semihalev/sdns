package recovery

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
)

// Recovery dummy type
type Recovery struct{}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
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
func (r *Recovery) ServeDNS(dc *ctx.Context) {
	defer func() {
		if r := recover(); r != nil {
			dc.DNSWriter.WriteMsg(dnsutil.HandleFailed(dc.DNSRequest, dns.RcodeServerFailure, false))

			log.Error("Recovered in ServeDNS", "recover", r)

			os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
			dc.Abort()
		}
	}()

	dc.NextDNS()
}

const name = "recovery"
