package ctx

import (
	"math"
	"net/http"

	"github.com/miekg/dns"
)

// Handler interface
type Handler interface {
	Name() string
	ServeDNS(*Context)
	ServeHTTP(*Context)
}

// Context type
type Context struct {
	DNSWriter  dns.ResponseWriter
	DNSRequest *dns.Msg

	HTTPWriter  http.ResponseWriter
	HTTPRequest *http.Request

	handlers []Handler
	index    int8
}

const abortIndex int8 = math.MaxInt8 / 2

// New return new dnscontext
func New(handlers []Handler) *Context {
	return &Context{
		handlers: handlers,
		index:    -1,
	}
}

// NextDNS call next dns middleware
func (dc *Context) NextDNS() {
	dc.index++
	for s := int8(len(dc.handlers)); dc.index < s; dc.index++ {
		dc.handlers[dc.index].ServeDNS(dc)
	}
}

// NextHTTP call next http middleware
func (dc *Context) NextHTTP() {
	dc.index++
	for s := int8(len(dc.handlers)); dc.index < s; dc.index++ {
		dc.handlers[dc.index].ServeHTTP(dc)
	}
}

// Abort calls
func (dc *Context) Abort() {
	dc.index = abortIndex
}

// ResetDNS reset dns vars
func (dc *Context) ResetDNS(w dns.ResponseWriter, r *dns.Msg) {
	dc.DNSRequest, dc.DNSWriter = r, w

	dc.index = -1
}

// ResetHTTP reset http vars
func (dc *Context) ResetHTTP(w http.ResponseWriter, r *http.Request) {
	dc.HTTPRequest, dc.HTTPWriter = r, w

	dc.index = -1
}
