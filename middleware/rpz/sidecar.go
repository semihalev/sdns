package rpz

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/sdns/middleware"
)

// storeGen numbers policy generations process-wide. Every published
// store carries one, and every sidecar candidate is stamped with the
// generation it was computed under — the single-object snapshot §5.6
// item 5 requires: a candidate can never pair old rules with a new
// generation, because both travel in the same *rpz.Store.
var storeGen atomic.Uint64

// policyStore is one published generation with its shared explicit-none
// sidecar. The none sentinel rides the same pointer as the rules, so an
// evaluator can never stamp one generation's none beside another's rules
// — and because it is shared, an admission that matched nothing
// allocates nothing per entry (§5.11's explicit-none clause).
type policyStore struct {
	*rpz.Store
	none *middleware.Sidecar
}

// publishStore assigns the next generation and swaps the store in.
// Every store swap in this package goes through here.
func (r *RPZ) publishStore(s *rpz.Store) {
	s.Gen = storeGen.Add(1)
	r.store.Store(&policyStore{
		Store: s,
		none:  &middleware.Sidecar{Value: &rpz.ResponseMatches{Gen: s.Gen}},
	})
}

// SidecarEvaluator implements middleware.SidecarPolicyProvider: the
// admission half of the cache seam. It evaluates a stored answer's
// records against the response-IP tables and returns the per-zone match
// list stamped with the generation it read — or the generation's shared
// none, so the overwhelmingly common clean admission allocates nothing.
// nil when the middleware is disabled, and a nil Sidecar when no zone
// carries response rules — the seam then stays entirely off.
func (r *RPZ) SidecarEvaluator() middleware.SidecarEvaluator {
	if !r.enabled {
		return nil
	}
	return func(msg *dns.Msg) *middleware.Sidecar {
		s := r.store.Load()
		if !s.HasResponseIP() {
			return nil
		}
		list := s.EvaluateResponseList(msg.Answer)
		if len(list) == 0 {
			return s.none
		}
		return &middleware.Sidecar{Value: &rpz.ResponseMatches{Gen: s.Gen, List: list}}
	}
}

// WireHitGate implements middleware.SidecarPolicyProvider: the serve
// half of the seam. nil when disabled.
func (r *RPZ) WireHitGate() middleware.WireHitGate {
	if !r.enabled {
		return nil
	}
	return r
}

// sidecarMatches unwraps a stamped sidecar; ok is false for nil or a
// foreign value.
func sidecarMatches(sc *middleware.Sidecar) (*rpz.ResponseMatches, bool) {
	if sc == nil {
		return nil, false
	}
	rm, ok := sc.Value.(*rpz.ResponseMatches)
	return rm, ok
}

// JudgeWireHit is the pure byte-serve decision over one entry's sidecar,
// and it is deliberately blunt: bytes serve only when the entry matched
// nothing. Any match — enforce or shadow, winner or loser — goes to the
// decoded path, because only this query's response wrap knows the held
// candidates and the §5.4 finality that make the winner-bounded count
// (and the action) correct; a decoded serve on a query whose decision
// already fell carries no wrap and stays silent, exactly as a zone past
// the winner must. That bluntness is also what keeps this judgment free
// of the judge/commit generation race: nothing countable ever rides the
// byte path, so there is nothing for a commit-time reload to miscount.
func (r *RPZ) JudgeWireHit(sc *middleware.Sidecar) middleware.WireHitVerdict {
	s := r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	rm, ok := sidecarMatches(sc)
	if !ok || rm.Gen != s.Gen {
		return middleware.WireHitRestamp
	}
	if len(rm.List) == 0 {
		return middleware.WireHitServe
	}
	return middleware.WireHitDecode
}

// JudgeWireChase judges a composed chase: any unevaluated or stale
// segment sends the hit to the decoded path to be restamped as it
// re-chases; any matching segment sends it there for the merge. The
// decoded chase composes the whole answer before the wrap evaluates it,
// so two segments matching one zone collapse to that zone's single
// rule-4 best by construction (§5.6 item 4).
func (r *RPZ) JudgeWireChase(chain middleware.SidecarChain) middleware.WireHitVerdict {
	s := r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	for i := 0; i < chain.Len(); i++ {
		rm, ok := sidecarMatches(chain.At(i))
		if !ok || rm.Gen != s.Gen {
			return middleware.WireHitRestamp
		}
		if len(rm.List) > 0 {
			return middleware.WireHitDecode
		}
	}
	return middleware.WireHitServe
}

// CountWireHit and CountWireChase are deliberately empty: the judge
// above never lets a matching entry serve bytes, so a committed byte
// serve is always a none — and none is counted as nothing. Every real
// count happens in the response wrap, which alone holds the query-time
// candidates the winner-bounded semantic is defined over.
func (r *RPZ) CountWireHit(*middleware.Sidecar)       {}
func (r *RPZ) CountWireChase(middleware.SidecarChain) {}

// wrapPool recycles response wraps: with response rules configured every
// query installs one, and the clean wire hit must not pay a heap
// allocation for it (§5.11). The wrap's lifetime is the Next call it
// brackets — the same discipline every writer wrapper in the tree keeps —
// so the put after the restore hands back an object nothing can reach.
var wrapPool = sync.Pool{New: func() any { return new(responseWrap) }}

// responseWrap is the response-side writer: it sees every decoded answer
// leaving this query — cache hit or fresh resolution — evaluates its
// records, merges them with the query-time candidates held under §5.4,
// and applies (enforce) or counts (shadow) the winning action. Byte
// serves pass through untouched: the gate admits only none entries.
type responseWrap struct {
	middleware.ResponseWriter
	r   *RPZ
	ctx context.Context

	// held is the enabled-zone query-time match §5.4 held; heldObserved
	// the disabled-zone matches gathered on the way. holding hides the
	// wire capability so every serve for this query is decoded — the
	// merge needs the message.
	held         rpz.ZoneMatch
	heldObserved []rpz.ZoneMatch
	holding      bool
}

// WriteMsg runs the serve-time merge on the outgoing decoded response.
func (w *responseWrap) WriteMsg(m *dns.Msg) error {
	s := w.r.store.Load()
	list := s.EvaluateResponseList(m.Answer)
	winner, observed := s.Merge(w.held, w.heldObserved, list)
	for _, o := range observed {
		countMatch(o, outcomeObserved)
	}
	if winner.Zone == nil {
		return w.ResponseWriter.WriteMsg(m)
	}
	if !w.r.enforce {
		countMatch(winner, outcomeObserved)
		if debugLogEnabled() {
			debugMatch("RPZ response match in shadow", winner)
		}
		return w.ResponseWriter.WriteMsg(m)
	}
	countMatch(winner, outcomeEnforced)
	return w.rewrite(m, winner)
}

// rewrite applies the winning action to the outgoing response. The
// synthesized replies mirror act()'s exactly; the truth is discarded.
func (w *responseWrap) rewrite(m *dns.Msg, winner rpz.ZoneMatch) error {
	do := hasDO(m)
	switch winner.Effective() {
	case rpz.ActionPassthru:
		return w.ResponseWriter.WriteMsg(m)
	case rpz.ActionDrop:
		// No reply at all: swallowing the write releases the query
		// without a response, the accesslist mechanism at this layer.
		return nil
	case rpz.ActionTCPOnly:
		if w.Proto() != "udp" {
			return w.ResponseWriter.WriteMsg(m)
		}
		tc := new(dns.Msg)
		tc.SetReply(m)
		tc.Question = m.Question
		tc.RecursionAvailable = true
		tc.Truncated = true
		return w.ResponseWriter.WriteMsg(tc)
	case rpz.ActionNXDOMAIN:
		reply := dnsutil.SetRcode(m, dns.RcodeNameError, do)
		stamp(reply, winner)
		return w.ResponseWriter.WriteMsg(reply)
	case rpz.ActionNODATA:
		reply := dnsutil.SetRcode(m, dns.RcodeSuccess, do)
		stamp(reply, winner)
		return w.ResponseWriter.WriteMsg(reply)
	case rpz.ActionLocalData:
		reply := w.r.buildLocalData(w.ctx, m, winner, do)
		return w.ResponseWriter.WriteMsg(reply)
	}
	return w.ResponseWriter.WriteMsg(m)
}

// hasDO reads the DO bit off the message's own OPT; the wrap sits below
// the edns layer, so the client's OPT is what the message carries.
func hasDO(m *dns.Msg) bool {
	if opt := m.IsEdns0(); opt != nil {
		return opt.Do()
	}
	return false
}

// The wire capability passes through untouched unless this query holds
// candidates: a held query must be answered from the decoded path, where
// the merge can see the message (§5.4).
func (w *responseWrap) WireReady() (middleware.WireCapability, bool) {
	if w.holding {
		return middleware.WireCapability{}, false
	}
	if ww, ok := w.ResponseWriter.(middleware.WireWriter); ok {
		return ww.WireReady()
	}
	return middleware.WireCapability{}, false
}

func (w *responseWrap) WriteWire(body []byte, info middleware.WireInfo) error {
	if ww, ok := w.ResponseWriter.(middleware.WireWriter); ok {
		return ww.WriteWire(body, info)
	}
	return middleware.ErrWireFallback
}

func (w *responseWrap) BeginWire(size, reserve int) []byte {
	if l, ok := w.ResponseWriter.(middleware.WireBodyLeaser); ok {
		return l.BeginWire(size, reserve)
	}
	return nil
}

func (w *responseWrap) CommitWire(body []byte, info middleware.WireInfo) error {
	if l, ok := w.ResponseWriter.(middleware.WireBodyLeaser); ok {
		return l.CommitWire(body, info)
	}
	return middleware.ErrWireFallback
}

func (w *responseWrap) AbortWire() {
	if l, ok := w.ResponseWriter.(middleware.WireBodyLeaser); ok {
		l.AbortWire()
	}
}
