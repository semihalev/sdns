package middleware

import (
	"context"

	"github.com/miekg/dns"
)

// Chain carries per-request state through the middleware pipeline.
// Instances are reused via a sync.Pool: NewChain allocates the fixed
// pipeline reference, Reset rebinds the per-request writer + message.
type Chain struct {
	Writer  ResponseWriter
	Request *dns.Msg

	handlers []Handler
	pos      int // index of the next handler to run
	count    int // handlers remaining; goes to 0 on Cancel
}

// NewChain returns a Chain bound to the given handler pipeline. The slice
// is captured by reference and must not be mutated by the caller after
// this call.
func NewChain(handlers []Handler) *Chain {
	return &Chain{
		Writer:   &responseWriter{},
		handlers: handlers,
		count:    len(handlers),
	}
}

// Next invokes the next handler in the chain. Each handler is responsible
// for calling Next to continue, or Cancel/CancelWithRcode to stop.
func (ch *Chain) Next(ctx context.Context) {
	if ch.count == 0 {
		return
	}
	h := ch.handlers[ch.pos]
	ch.pos++
	ch.count--
	h.ServeDNS(ctx, ch)
}

// Cancel stops the chain without writing a response. Subsequent Next
// calls become no-ops.
func (ch *Chain) Cancel() {
	ch.count = 0
}

// CancelWithRcode writes a reply with the given rcode and stops the
// chain. do controls the DO bit in the response's OPT record.
func (ch *Chain) CancelWithRcode(rcode int, do bool) {
	m := new(dns.Msg)
	m.Extra = ch.Request.Extra
	m.SetRcode(ch.Request, rcode)
	m.RecursionAvailable = true
	m.RecursionDesired = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(do)
	}

	_ = ch.Writer.WriteMsg(m)
	ch.count = 0
}

// Reset rebinds the chain to a fresh writer + request for pool reuse.
func (ch *Chain) Reset(w dns.ResponseWriter, r *dns.Msg) {
	ch.Writer.Reset(w)
	ch.Request = r
	ch.pos = 0
	ch.count = len(ch.handlers)
}
