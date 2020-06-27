package ctx

import (
	"context"

	"github.com/miekg/dns"
)

// Handler interface
type Handler interface {
	Name() string
	ServeDNS(context.Context, *Context)
}

// Context type
type Context struct {
	DNSWriter  ResponseWriter
	DNSRequest *dns.Msg

	handlers []Handler
	next     int8
}

// New return new dnscontext
func New(handlers []Handler) *Context {
	return &Context{
		DNSWriter: &responseWriter{},
		handlers:  handlers,
		next:      -1,
	}
}

// NextDNS call next dns handler in chain
func (dc *Context) NextDNS(ctx context.Context) {
	dc.next++

	for cnt := int8(len(dc.handlers)); dc.next < cnt; dc.next++ {
		dc.handlers[dc.next].ServeDNS(ctx, dc)
	}
}

// Cancel next calls
func (dc *Context) Cancel() {
	dc.next = cancel
}

// Reset the context variables
func (dc *Context) Reset(w dns.ResponseWriter, r *dns.Msg) {
	dc.DNSWriter.Reset(w)
	dc.DNSRequest = r

	dc.next = -1
}

const cancel int8 = 1<<6 - 1
