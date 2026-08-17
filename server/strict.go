package server

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// The strict path: eligible packets enter the chain as a wire-born
// middleware.Request on the job carrier — no decoded message, no
// per-request context allocation. Eligibility (Request.ParseWire) is
// conservative: exactly one question over an uncompressed
// name, empty answer/authority, at most one well-formed root OPT, plain
// query opcode. Anything else decodes and takes the ordinary entry, which
// allocates freely.

// jobCarrier is the job-owned contextutil.Carrier: fixed pin slots and a
// provider hook behind a cheap mutex (a job serves on one goroutine; the
// lock is uncontended and exists for the interface's safety contract),
// no Done channel — cancellation is not observable on a path that never
// blocks, and the composite-miss transition detaches to a real context
// before anything can.
type jobCarrier struct {
	deadline time.Time

	mu       sync.Mutex
	keys     [4]any
	vals     [4]any
	provider contextutil.ValueProvider
}

// reset prepares the carrier for the next request; the engine calls it
// before every strict serve, so a recycled job can never leak pins.
func (c *jobCarrier) reset(deadline time.Time) {
	c.mu.Lock()
	c.deadline = deadline
	c.keys = [4]any{}
	c.vals = [4]any{}
	c.provider = nil
	c.mu.Unlock()
}

func (c *jobCarrier) Deadline() (time.Time, bool) { return c.deadline, true }
func (c *jobCarrier) Done() <-chan struct{}       { return nil }
func (c *jobCarrier) Err() error                  { return nil }

func (c *jobCarrier) Value(key any) any {
	if v, ok := contextutil.CarrierLookup(c, key); ok {
		return v
	}
	c.mu.Lock()
	provider := c.provider
	c.mu.Unlock()
	if provider != nil {
		if v, ok := provider.ContextValue(key); ok {
			return v
		}
	}
	return nil
}

func (c *jobCarrier) TryPin(key, value any) bool {
	if key == nil || value == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	free := -1
	for i := range c.keys {
		if c.keys[i] == key {
			return false
		}
		if c.keys[i] == nil && free < 0 {
			free = i
		}
	}
	if free < 0 {
		return false
	}
	c.keys[free] = key
	c.vals[free] = value
	return true
}

func (c *jobCarrier) Pinned(key any) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.keys {
		if c.keys[i] == key {
			return c.vals[i], true
		}
	}
	return nil, false
}

func (c *jobCarrier) UpdatePinLocked(key any, update func(any) (any, bool)) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.keys {
		if c.keys[i] != key {
			continue
		}
		next, ok := update(c.vals[i])
		if !ok || next == nil {
			return c.vals[i], false
		}
		c.vals[i] = next
		return next, true
	}
	return nil, false
}

// UpdatePinTransitionLocked implements contextutil.Carrier; the body
// mirrors UpdatePinLocked with the transition on an interface instead of
// a closure.
func (c *jobCarrier) UpdatePinTransitionLocked(key any, t contextutil.PinTransition) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.keys {
		if c.keys[i] != key {
			continue
		}
		next, ok := t.NextLocked(c.vals[i])
		if !ok || next == nil {
			return c.vals[i], false
		}
		c.vals[i] = next
		return next, true
	}
	return nil, false
}

func (c *jobCarrier) TrySetProvider(p contextutil.ValueProvider) bool {
	if p == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return false
	}
	c.provider = p
	return true
}

// rawHandler is the engines' one ingress contract: raw bytes in;
// eligibility, decode, and context are the server's business. A false
// return means the payload was undecodable — the engine answers with its
// in-place wire FORMERR, keeping the rejection in job storage.
type rawHandler interface {
	ServeRaw(w middleware.Transport, raw []byte, readTime time.Time) bool
}

// inlineRawHandler is the optional fast-path contract: a handler that can
// run a query on the transport reader without blocking, handing off what
// needs a worker. Engines type-assert it once at construction and consult
// InlineReady — a handler whose pipeline carries no middleware.InlineBarrier
// must not serve inline, or the reader would block in the resolver. A
// handler without the interface (test stubs) simply keeps every query on
// the ring.
type inlineRawHandler interface {
	rawHandler
	InlineReady() bool
	ServeRawInline(w middleware.Transport, raw []byte, readTime time.Time) bool
	ServeRawReplay(w middleware.Transport, raw []byte, readTime time.Time) bool
}

// strictSlots is what an SDNS-owned transport job offers ServeRaw:
// job-owned storage for the request, the context carrier, and the edns
// writer wrapper.
type strictSlots interface {
	StrictSlots() (*middleware.Request, *middleware.Chain, *jobCarrier, *edns.ResponseWriter)
}

// The owned transports must satisfy it. The match is structural, so a
// signature change would otherwise drop them onto the decoding path in
// silence — no compile error, no test failure until an allocation gate
// notices, which is how it was found the first time.
var (
	_ strictSlots = (*udpJob)(nil)
	_ strictSlots = (*tcpJob)(nil)
)

// ServeRaw is the single raw-transport ingress. An eligible packet on a
// job transport enters the chain as a wire-born request on the job carrier
// — no decode, no context allocation; anything else decodes here and takes
// the ordinary lazy-deadline entry with the direct-pack capability (the
// owned transports are raw byte sinks).
func (s *Server) ServeRaw(w middleware.Transport, raw []byte, readTime time.Time) bool {
	if s.trimEnabled {
		s.served.Add(1)
	}
	if job, ok := w.(strictSlots); ok {
		req, chain, carrier, ednsSlot := job.StrictSlots()
		if req.ParseWire(raw, readTime, ednsSlot) {
			carrier.reset(readTime.Add(s.queryTimeout()))
			s.serveWire(carrier, w, req, chain)
			return true
		}
	}

	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		// Accepted header, undecodable body: engine-side FORMERR parity.
		return false
	}
	// The decoded fallback is the slow lane by definition — the same
	// reason a strict materialization flushes applies from the first
	// instruction here: replies already staged on this transport must
	// not wait out this query's resolution.
	if f, ok := w.(middleware.StagedFlusher); ok {
		f.FlushStaged()
	}
	s.serveMsgBy(context.Background(), w, m, true, readTime.Add(s.queryTimeout()))
	return true
}

// ServeRawInline is ServeRaw for a transport reader that must not block:
// the full chain runs with the inline-only mark, and the cache — the one
// handler whose downstream can block on the network — declines a query it
// cannot answer from its wire ladder, unwritten. handled reports whether
// the query reached a terminal here; a false return with handoff true
// means the caller owns an admitted, guarded, unanswered job it must
// replay on a worker with ServeRawReplay. A packet the strict path cannot
// carry is a handoff outright: the decoded fallback resolves, and
// resolving blocks.
func (s *Server) ServeRawInline(w middleware.Transport, raw []byte, readTime time.Time) (handled bool) {
	if job, ok := w.(strictSlots); ok {
		req, chain, carrier, ednsSlot := job.StrictSlots()
		if req.ParseWire(raw, readTime, ednsSlot) {
			if s.trimEnabled {
				s.served.Add(1)
			}
			carrier.reset(readTime.Add(s.queryTimeout()))
			if s.pipeline == nil || contextutil.EffectiveError(carrier) != nil {
				return true
			}
			s.pipeline.BindChain(chain)
			defer chain.Finish()
			chain.ResetWire(w, req)
			chain.AllowDirectPack()
			chain.SetInlineOnly()
			chain.Next(carrier)
			return !chain.Handoff()
		}
	}
	return false
}

// InlineReady reports whether the pipeline carries an inline barrier; the
// engines enable the reader fast path only when it does.
func (s *Server) InlineReady() bool { return s.inlineReady }

// ServeRawReplay finishes a query the inline pass handed off. The full
// pipeline runs with the replay mark: handlers whose entry effects fired
// on the inline pass skip them, and the middlewares that key off the
// response fire here, once, when this pass writes.
func (s *Server) ServeRawReplay(w middleware.Transport, raw []byte, readTime time.Time) bool {
	// No served count here for the strict branch: the inline pass already
	// counted this query. The decoded fallback below never ran inline.
	if job, ok := w.(strictSlots); ok {
		req, chain, carrier, ednsSlot := job.StrictSlots()
		if req.ParseWire(raw, readTime, ednsSlot) {
			carrier.reset(readTime.Add(s.queryTimeout()))
			if s.pipeline == nil {
				return true
			}
			if contextutil.EffectiveError(carrier) != nil {
				return true
			}
			s.pipeline.BindChain(chain)
			defer chain.Finish()
			chain.ResetWire(w, req)
			chain.AllowDirectPack()
			chain.SetReplay()
			chain.Next(carrier)
			return true
		}
	}

	if s.trimEnabled {
		s.served.Add(1)
	}
	m := new(dns.Msg)
	if err := m.Unpack(raw); err != nil {
		return false
	}
	if f, ok := w.(middleware.StagedFlusher); ok {
		f.FlushStaged()
	}
	s.serveMsgBy(context.Background(), w, m, true, readTime.Add(s.queryTimeout()))
	return true
}

// serveWire runs one wire-born request through the pipeline on the job
// carrier. No deadline context, no decoded message — the composite-miss
// transition inside the chain builds both when, and only when, they are
// needed.
func (s *Server) serveWire(
	ctx context.Context,
	w middleware.Transport,
	req *middleware.Request,
	ch *middleware.Chain,
) {
	if s.pipeline == nil {
		return
	}
	if contextutil.EffectiveError(ctx) != nil {
		return
	}
	// The chain is the transport's own storage; binding restates the
	// pipeline's immutable handler list over it, and Finish closes what
	// a mid-chain materialization opened. Nothing here is pooled.
	s.pipeline.BindChain(ch)
	defer ch.Finish()

	ch.ResetWire(w, req)
	ch.AllowDirectPack()
	ch.Next(ctx)
}
