// Package loop detects DNS query loops caused by middleware recursion.
// The loop counter rides on context so it survives the chain boundaries
// that util.ExchangeInternal introduces: every nested exchange gets a
// fresh Chain from the pool but inherits the caller's ctx.
package loop

import (
	"context"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// Loop detects query loops.
type Loop struct{}

// loopKey identifies a distinct (qname, qtype) pair inside the tracker's
// map. Stays a pure-value struct so map operations don't allocate.
type loopKey struct {
	name  string
	qtype uint16
}

// tracker accumulates per-question counts for a single end-to-end
// request. It is installed into ctx on the first chain re-entry and
// reused by every further re-entry.
type tracker struct {
	mu     sync.Mutex
	counts map[loopKey]uint32
}

// trackerCtxKey is a zero-value unique sentinel; using a pointer type
// makes ctx.Value(trackerCtxKey) interface boxing allocation-free.
type trackerCtxKeyType struct{}

var trackerCtxKey = &trackerCtxKeyType{}

// maxLoops is the threshold beyond which a question is declared a loop.
const maxLoops = 10

// New return loop.
func New(cfg *config.Config) *Loop { return &Loop{} }

// (*Loop).Name name return middleware name.
func (l *Loop) Name() string { return name }

// (*Loop).ServeDNS serveDNS implements the Handle interface.
//
// Loop detection only runs on chain re-entries. A chain is a re-entry
// when it was dispatched via util.ExchangeInternal — that path uses a
// mock.Writer whose RemoteAddr is the internal sentinel, so
// ch.Writer.Internal() is true. Every external client query bypasses
// the tracker entirely, keeping the normal hot path at zero allocations.
func (l *Loop) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req := ch.Request

	if len(req.Question) == 0 {
		ch.Cancel()
		return
	}

	if !ch.Writer.Internal() {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	k := loopKey{name: q.Name, qtype: q.Qtype}

	t, _ := ctx.Value(trackerCtxKey).(*tracker)
	if t == nil {
		t = &tracker{counts: map[loopKey]uint32{k: 1}}
		ch.Next(context.WithValue(ctx, trackerCtxKey, t))
		return
	}

	t.mu.Lock()
	n := t.counts[k] + 1
	t.counts[k] = n
	t.mu.Unlock()

	if n > maxLoops {
		zlog.Warn("Loop detected", "qname", q.Name, "qtype", dns.TypeToString[q.Qtype])
		ch.CancelWithRcode(dns.RcodeServerFailure, false)
		return
	}

	ch.Next(ctx)
}

const name = "loop"
