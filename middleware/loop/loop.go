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
// map. The name is a 64-bit case-insensitive FNV-1a hash rather than
// the raw string so map lookups don't allocate a lowercased copy of
// every qname on each chain re-entry. For the small (<16) number of
// distinct questions a single request re-enters, FNV-1a collisions are
// astronomically rare — and a collision here only conflates two
// loop counters, it cannot cause a wrong answer.
type loopKey struct {
	name  uint64
	qtype uint16
}

// FNV-1a 64-bit constants, inlined so hashing qname in ServeDNS costs
// zero allocations.
const (
	fnv64Offset = 14695981039346656037
	fnv64Prime  = 1099511628211
)

// hashLower returns the 64-bit FNV-1a hash of s with ASCII letters
// folded to lower case on the fly. DNS names are ASCII per RFC 1035,
// and 0x20-mixed variants (`Foo.Example.com.` vs `foo.example.com.`)
// must produce the same key so a re-entry isn't silently duplicated.
func hashLower(s string) uint64 {
	h := uint64(fnv64Offset)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		h ^= uint64(c)
		h *= fnv64Prime
	}
	return h
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
	k := loopKey{name: hashLower(q.Name), qtype: q.Qtype}

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
