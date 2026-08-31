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

// The globally wired gate serves the queries rpz never wrapped — the
// exempt ones its own ServeDNS gates out (internal, RD=0, non-INET) and
// deployments without response rules. It is neutral: it keeps entries
// healthy (a stale sidecar still restamps) and serves everything else as
// bytes, counting nothing, because policy does not apply to those
// queries at all. Every policed query carries its own gate on the
// response wrap (middleware.QueryPolicyGate), which is how held
// candidates and §5.4 finality reach the byte-serve judgment.
func (r *RPZ) JudgeWireHit(sc *middleware.Sidecar) middleware.WireHitVerdict {
	return r.neutralJudge(sc)
}

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
	}
	return middleware.WireHitServe
}

func (r *RPZ) CountWireHit(*middleware.Sidecar)       {}
func (r *RPZ) CountWireChase(middleware.SidecarChain) {}

func (r *RPZ) neutralJudge(sc *middleware.Sidecar) middleware.WireHitVerdict {
	s := r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	if rm, ok := sidecarMatches(sc); !ok || rm.Gen != s.Gen {
		return middleware.WireHitRestamp
	}
	return middleware.WireHitServe
}

// wrapPool recycles response wraps: with response rules configured every
// query installs one, and the clean wire hit must not pay a heap
// allocation for it (§5.11). The wrap's lifetime is the Next call it
// brackets — the same discipline every writer wrapper in the tree keeps —
// so the put after the restore hands back an object nothing can reach.
var wrapPool = sync.Pool{New: func() any { return new(responseWrap) }}

// wrapMode is what this query's wrap owes the response side.
type wrapMode uint8

const (
	// wrapPoliced: no query-time winner; the byte path may serve, its
	// gate judging and counting through this wrap, and every decoded
	// answer runs the merge in WriteMsg.
	wrapPoliced wrapMode = iota
	// wrapHold: a query-time candidate is held under §5.4; the wire
	// capability is withheld so the merge sees every answer decoded.
	wrapHold
	// wrapBypass: the query's decision already fell (a final winner
	// continuing in shadow or under PASSTHRU); the response side serves
	// bytes freely and counts nothing — zones past the winner stay
	// silent in both modes.
	wrapBypass
)

// responseWrap is the response-side writer and this query's own wire-hit
// gate: it sees every decoded answer leaving the query — cache hit or
// fresh resolution — evaluates its records, merges them with the
// query-time candidates held under §5.4, and applies (enforce) or counts
// (shadow) the winning action; on the byte path its gate judges the
// entry's sidecar with the same merge and memoizes the decision, so the
// count after the commit records exactly what was judged and served,
// whatever a concurrent reload does in between.
type responseWrap struct {
	middleware.ResponseWriter
	r    *RPZ
	ctx  context.Context
	mode wrapMode

	// held is the enabled-zone query-time match §5.4 held; heldObserved
	// the disabled-zone matches gathered on the way.
	held         rpz.ZoneMatch
	heldObserved []rpz.ZoneMatch

	// The decision token: the merge the gate judged Serve with, counted
	// verbatim at the commit. Judge and commit run on one goroutine
	// within one hit, and the wrap resets between queries.
	decided         bool
	decidedWinner   rpz.ZoneMatch
	decidedObserved []rpz.ZoneMatch
}

// QueryWireHitGate hands the cache this query's own gate
// (middleware.QueryPolicyGate).
func (w *responseWrap) QueryWireHitGate() middleware.WireHitGate { return w }

// JudgeWireHit is the byte-serve decision with the query's context: the
// entry's matches merge with the held disabled observations, and any
// outcome that leaves the stored answer intact — nothing matched, no
// enabled winner, shadow, an enforcing PASSTHRU — serves bytes, with the
// decision memoized for the commit-time count. Only an enforcing rewrite
// needs the decoded path. A bypass wrap serves everything and decides
// nothing; a holding wrap never reaches here (its wire is withheld).
func (w *responseWrap) JudgeWireHit(sc *middleware.Sidecar) middleware.WireHitVerdict {
	s := w.r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	rm, ok := sidecarMatches(sc)
	if !ok || rm.Gen != s.Gen {
		return middleware.WireHitRestamp
	}
	if w.mode != wrapPoliced {
		return middleware.WireHitServe
	}
	return w.judgeList(s, rm.List)
}

// JudgeWireChase is JudgeWireHit over a composed chase: every segment
// must be evaluated and current, and the folded per-zone bests (§5.6
// item 4's dedupe) enter the same merge.
func (w *responseWrap) JudgeWireChase(chain middleware.SidecarChain) middleware.WireHitVerdict {
	s := w.r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	lists := make([][]rpz.ResponseMatch, 0, middleware.SidecarChainCap)
	for i := 0; i < chain.Len(); i++ {
		rm, ok := sidecarMatches(chain.At(i))
		if !ok || rm.Gen != s.Gen {
			return middleware.WireHitRestamp
		}
		lists = append(lists, rm.List)
	}
	if w.mode != wrapPoliced {
		return middleware.WireHitServe
	}
	return w.judgeList(s, rpz.FoldResponseLists(lists...))
}

func (w *responseWrap) judgeList(s *policyStore, list []rpz.ResponseMatch) middleware.WireHitVerdict {
	if len(list) == 0 && len(w.heldObserved) == 0 {
		// The steady state: nothing to merge, nothing to count.
		return middleware.WireHitServe
	}
	winner, observed := s.Merge(rpz.ZoneMatch{}, w.heldObserved, list)
	if winner.Zone != nil && w.r.enforce && winner.Effective() != rpz.ActionPassthru {
		w.decided = false
		return middleware.WireHitDecode
	}
	w.decided, w.decidedWinner, w.decidedObserved = true, winner, observed
	return middleware.WireHitServe
}

// CountWireHit and CountWireChase record the memoized decision after the
// bytes were committed — exactly once, exactly what was judged.
func (w *responseWrap) CountWireHit(*middleware.Sidecar)       { w.countDecided() }
func (w *responseWrap) CountWireChase(middleware.SidecarChain) { w.countDecided() }

func (w *responseWrap) countDecided() {
	if !w.decided {
		return
	}
	w.decided = false
	for _, o := range w.decidedObserved {
		countMatch(o, outcomeObserved)
	}
	if w.decidedWinner.Zone == nil {
		return
	}
	if w.r.enforce {
		// A byte serve committed under an enforcing winner means the
		// action was PASSTHRU — acting, by not acting.
		countMatch(w.decidedWinner, outcomeEnforced)
		return
	}
	countMatch(w.decidedWinner, outcomeObserved)
	if debugLogEnabled() {
		debugMatch("RPZ response match in shadow", w.decidedWinner)
	}
}

// WriteMsg runs the serve-time merge on the outgoing decoded response.
func (w *responseWrap) WriteMsg(m *dns.Msg) error {
	if w.mode == wrapBypass {
		return w.ResponseWriter.WriteMsg(m)
	}
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
	if w.mode == wrapHold {
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
