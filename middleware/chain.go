package middleware

import (
	"context"

	"github.com/miekg/dns"
)

// Chain type
type Chain struct {
	Writer  ResponseWriter
	Request *dns.Msg

	handlers []Handler

	head  int
	tail  int
	count int
}

// NewChain return new fresh chain
func NewChain(handlers []Handler) *Chain {
	return &Chain{
		Writer:   &responseWriter{},
		handlers: handlers,
		count:    len(handlers),
	}
}

// Next call next dns handler in the chain
func (ch *Chain) Next(ctx context.Context) {
	if ch.count == 0 {
		return
	}

	handler := ch.handlers[ch.head]
	ch.head = (ch.head + 1) % len(ch.handlers)
	ch.count--

	handler.ServeDNS(ctx, ch)
}

// Cancel next calls
func (ch *Chain) Cancel() {
	ch.count = 0
}

// CancelWithRcode next calls with rcode
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

// Reset the chain variables
func (ch *Chain) Reset(w dns.ResponseWriter, r *dns.Msg) {
	ch.Writer.Reset(w)
	ch.Request = r
	ch.count = len(ch.handlers)
	ch.head, ch.tail = 0, 0
}
