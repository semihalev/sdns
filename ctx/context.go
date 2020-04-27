package ctx

import (
	"context"
	"math"

	"github.com/miekg/dns"
)

// Handler interface
type Handler interface {
	Name() string
	ServeDNS(*Context)
}

// Context type
type Context struct {
	DNSWriter  ResponseWriter
	DNSRequest *dns.Msg

	Context context.Context

	handlers []Handler
	index    int8
}

const abortIndex int8 = math.MaxInt8 / 2

// New return new dnscontext
func New(handlers []Handler) *Context {
	return &Context{
		DNSWriter: &responseWriter{},
		handlers:  handlers,
		index:     -1,
	}
}

// NextDNS call next dns middleware
func (dc *Context) NextDNS() {
	dc.index++
	for s := int8(len(dc.handlers)); dc.index < s; dc.index++ {
		dc.handlers[dc.index].ServeDNS(dc)
	}
}

// Abort calls
func (dc *Context) Abort() {
	dc.index = abortIndex
	dc.Context.Done()
}

// ResetDNS reset dns vars
func (dc *Context) ResetDNS(w dns.ResponseWriter, r *dns.Msg) {
	dc.DNSWriter.Reset(w)
	dc.DNSRequest = r

	dc.index = -1
	dc.Context = context.Background()
}
