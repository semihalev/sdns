package recovery

import (
	"fmt"
	"net/http"
	"os"
	"runtime/debug"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/ctx"
)

// Recovery dummy type
type Recovery struct{}

// Name return middleware name
func (r *Recovery) Name() string { return "recovery" }

// ServeDNS implements the Handle interface.
func (r *Recovery) ServeDNS(dc *ctx.Context) {
	defer func() {
		if r := recover(); r != nil {
			dns.HandleFailed(dc.DNSWriter, dc.DNSRequest)

			log.Error("Recovered in ServeDNS", "recover", r)

			os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
			dc.Abort()
		}
	}()

	dc.NextDNS()
}

func (r *Recovery) ServeHTTP(dc *ctx.Context) {
	defer func() {
		if r := recover(); r != nil {
			http.Error(dc.HTTPWriter, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

			log.Error("Recovered in ServeHTTP", "recover", r)

			os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
			dc.Abort()
		}
	}()

	dc.NextHTTP()
}
