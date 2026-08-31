package rpz

import (
	"context"
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

// publishStore assigns the next generation and swaps the store in.
// Every store swap in this package goes through here.
func (r *RPZ) publishStore(s *rpz.Store) {
	s.Gen = storeGen.Add(1)
	r.store.Store(s)
}

// SidecarEvaluator implements middleware.SidecarPolicyProvider: the
// admission half of the cache seam. It evaluates a stored answer's
// records against the response-IP tables and returns the uniform
// per-zone match list, stamped with the generation it read. nil when the
// middleware is disabled, and a nil Sidecar when no zone carries
// response rules — the seam then stays entirely off.
func (r *RPZ) SidecarEvaluator() middleware.SidecarEvaluator {
	if !r.enabled {
		return nil
	}
	return func(msg *dns.Msg) *middleware.Sidecar {
		rm := r.store.Load().EvaluateResponse(msg.Answer)
		if rm == nil {
			return nil
		}
		return &middleware.Sidecar{Value: rm}
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

// JudgeWireHit is the pure byte-serve decision over one entry's sidecar.
// Held query-time candidates never reach this path: a holding query's
// writer withholds its wire capability, so the gate only ever judges the
// response side (§5.6 item 6).
func (r *RPZ) JudgeWireHit(sc *middleware.Sidecar) middleware.WireHitVerdict {
	s := r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	rm, ok := sidecarMatches(sc)
	if !ok || rm.Gen != s.Gen {
		return middleware.WireHitRestamp
	}
	return r.judgeList(s, rm.List)
}

// JudgeWireChase judges a composed chase: any unevaluated or stale
// segment sends the whole hit to the decoded path, whose per-segment
// internal serves restamp as they chase; otherwise the folded lists are
// judged exactly like an exact hit.
func (r *RPZ) JudgeWireChase(chain middleware.SidecarChain) middleware.WireHitVerdict {
	s := r.store.Load()
	if !s.HasResponseIP() {
		return middleware.WireHitServe
	}
	folded, ok := r.foldChain(s, chain)
	if !ok {
		return middleware.WireHitRestamp
	}
	return r.judgeList(s, folded)
}

// judgeList maps a merge over the response candidates to a verdict:
// no enabled winner serves the truth; in shadow everything serves (the
// count happens at the commit); in enforce a PASSTHRU winner serves and
// anything else needs the decoded path to synthesize.
func (r *RPZ) judgeList(s *rpz.Store, list []rpz.ResponseMatch) middleware.WireHitVerdict {
	if len(list) == 0 {
		return middleware.WireHitServe
	}
	winner, _ := s.Merge(rpz.ZoneMatch{}, nil, list)
	if winner.Zone == nil || !r.enforce {
		return middleware.WireHitServe
	}
	if winner.Effective() == rpz.ActionPassthru {
		return middleware.WireHitServe
	}
	return middleware.WireHitDecode
}

// CountWireHit records a committed byte serve's policy outcome under the
// winner-bounded semantic — the byte path is the only place this hit's
// outcome still exists (§5.5).
func (r *RPZ) CountWireHit(sc *middleware.Sidecar) {
	s := r.store.Load()
	rm, ok := sidecarMatches(sc)
	if !ok || rm.Gen != s.Gen {
		return
	}
	r.countList(s, rm.List)
}

// CountWireChase is CountWireHit over the folded chase.
func (r *RPZ) CountWireChase(chain middleware.SidecarChain) {
	s := r.store.Load()
	folded, ok := r.foldChain(s, chain)
	if !ok {
		return
	}
	r.countList(s, folded)
}

func (r *RPZ) countList(s *rpz.Store, list []rpz.ResponseMatch) {
	if len(list) == 0 {
		return
	}
	winner, observed := s.Merge(rpz.ZoneMatch{}, nil, list)
	for _, o := range observed {
		countMatch(o, outcomeObserved)
	}
	if winner.Zone == nil {
		return
	}
	if r.enforce {
		// A byte serve committed under an enforcing winner means the
		// action was PASSTHRU — acting, by not acting.
		countMatch(winner, outcomeEnforced)
		return
	}
	countMatch(winner, outcomeObserved)
}

// foldChain gen-checks every segment and folds their lists per zone by
// the rank key. ok is false when any segment is unevaluated or stale.
func (r *RPZ) foldChain(s *rpz.Store, chain middleware.SidecarChain) ([]rpz.ResponseMatch, bool) {
	lists := make([][]rpz.ResponseMatch, 0, chain.Len())
	for i := 0; i < chain.Len(); i++ {
		rm, ok := sidecarMatches(chain.At(i))
		if !ok || rm.Gen != s.Gen {
			return nil, false
		}
		lists = append(lists, rm.List)
	}
	return rpz.FoldResponseLists(lists...), true
}

// responseWrap is the response-side writer: it sees every decoded answer
// leaving this query — cache hit or fresh resolution — evaluates its
// records, merges them with the query-time candidates held under §5.4,
// and applies (enforce) or counts (shadow) the winning action. Byte
// serves pass through untouched: the gate judged and counted them.
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
	var list []rpz.ResponseMatch
	if rm := s.EvaluateResponse(m.Answer); rm != nil {
		list = rm.List
	}
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
			zlog_debugResponse(winner)
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

func zlog_debugResponse(winner rpz.ZoneMatch) {
	debugMatch("RPZ response match in shadow", winner)
}
