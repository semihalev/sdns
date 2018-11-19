package recovery

import (
	"fmt"
	"os"
	"runtime/debug"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
)

// Recovery dummy type
type Recovery struct{}

// Name return middleware name
func (r *Recovery) Name() string { return "recovery" }

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
