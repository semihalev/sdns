// Package reflex detects DNS amplification/reflection attacks.
//
// This middleware focuses specifically on identifying spoofed source IPs
// used in DNS amplification attacks. It does NOT duplicate:
//   - Rate limiting (handled by ratelimit middleware)
//   - Blocklist/whitelist (handled by blocklist middleware)
//   - ANY query blocking (handled by resolver middleware)
//
// Detection strategy:
//  1. Track amplification ratio per IP (response size / request size)
//  2. Identify IPs with suspicious query patterns (only high-amp types, no normal queries)
//  3. Score IPs based on reflection attack likelihood
//  4. Block or challenge IPs exceeding threshold
package reflex

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// High amplification query types and their typical amplification factors
var ampFactors = map[uint16]float64{
	dns.TypeDNSKEY: 20.0, // DNSSEC key records
	dns.TypeRRSIG:  15.0, // DNSSEC signatures
	dns.TypeDS:     5.0,  // Delegation signer
	dns.TypeTXT:    10.0, // Text records (SPF, DKIM, etc.)
	dns.TypeNS:     5.0,  // Nameserver records
	dns.TypeMX:     4.0,  // Mail exchange
	dns.TypeSOA:    3.0,  // Start of authority
	dns.TypeSRV:    4.0,  // Service records
}

// Reflex detects DNS amplification/reflection attacks.
type Reflex struct {
	cfg *config.Config

	// IP tracking with bounded memory
	tracker *IPTracker

	// Shutdown
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates a new Reflex instance.
func New(cfg *config.Config) *Reflex {
	if !cfg.ReflexEnabled {
		return nil
	}

	r := &Reflex{
		cfg:     cfg,
		tracker: NewIPTracker(100_000), // Max 100K IPs (~10MB)
		done:    make(chan struct{}),
	}

	// Background cleanup
	r.wg.Add(1)
	go r.cleanup()

	zlog.Info("Reflex initialized",
		"mode", r.mode(),
		"threshold", r.threshold())

	return r
}

func (r *Reflex) mode() string {
	if r.cfg.ReflexLearningMode {
		return "learning"
	}
	if r.cfg.ReflexBlockMode {
		return "blocking"
	}
	return "monitor"
}

func (r *Reflex) threshold() float64 {
	if r.cfg.ReflexThreshold > 0 && r.cfg.ReflexThreshold <= 1.0 {
		return r.cfg.ReflexThreshold
	}
	return 0.7 // Default: 70% confidence to block
}

// Name returns middleware name.
func (r *Reflex) Name() string {
	return "reflex"
}

// ClientOnly marks reflex as client-traffic-only; amplification
// detection is a property of client query patterns, and
// middleware.Setup excludes it from internal sub-pipelines so
// internal sub-queries don't trip detection heuristics.
func (r *Reflex) ClientOnly() bool { return true }

// ServeDNS processes queries for amplification attack detection. The
// scoring facts — qtype and request wire length — come from the parsed
// request, so a wire-born query is scored without decoding; only the
// suspicious path materializes (for its logs and the BADCOOKIE-style
// refusal).
func (r *Reflex) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w := ch.Writer

	// Skip internal/loopback/TCP (can't spoof TCP)
	if w.Internal() || w.RemoteIP() == nil || w.RemoteIP().IsLoopback() {
		ch.Next(ctx)
		return
	}

	// The replay pass finishes a query the inline pass already scored;
	// recording it again would double its contribution and could tip a
	// legitimate client over the threshold. What this pass owns is the
	// response — the inline pass handed off unwritten — so only the
	// response-size wrapper installs, and the tracker still learns the
	// amplification the resolution actually achieved.
	if ch.Replay() {
		if qtype, reqLen, ok := requestFacts(ch.Request); ok && getAmpFactor(qtype) > 1.0 {
			defer r.wrapAmpTracking(ch, w.RemoteIP().String(), reqLen)()
		}
		ch.Next(ctx)
		return
	}

	// Only analyze UDP — other transports have an established
	// peer and aren't spoofing vectors. DoH/DoQ came in as
	// "doh"/"doq" and were still scored as if they were
	// spoofed UDP, so high-amplification DoH/DoQ clients
	// could be refused for no good reason.
	switch w.Proto() {
	case "tcp", "doh", "doq":
		r.tracker.RecordTCP(w.RemoteIP().String())
		ch.Next(ctx)
		return
	}

	qtype, reqLen, ok := requestFacts(ch.Request)
	if !ok {
		ch.Next(ctx)
		return
	}

	ip := w.RemoteIP().String()

	// Calculate amplification potential
	ampFactor := getAmpFactor(qtype)

	// Record this query
	score := r.tracker.RecordQuery(ip, qtype, ampFactor, reqLen)

	// Check if IP exceeds threshold
	threshold := r.threshold()
	if score >= threshold {
		r.handleSuspicious(ctx, ch, ip, score)
		return
	}

	// Only wrap response writer for high-amp queries to track amplification.
	// Normal queries (ampFactor <= 1.0) skip wrapping for better performance.
	if ampFactor > 1.0 {
		defer r.wrapAmpTracking(ch, ip, reqLen)()
	}

	ch.Next(ctx)
}

// wrapAmpTracking installs the response-size wrapper and returns the
// restore. Chains come from a sync.Pool, so the wrapper must be removed
// before returning — otherwise a later request starts with a stale reflex
// wrapper that tracks responses against an unrelated source IP.
func (r *Reflex) wrapAmpTracking(ch *middleware.Chain, ip string, reqLen int) func() {
	orig := ch.Writer
	ch.Writer = &responseWriter{
		ResponseWriter: orig,
		reqLen:         reqLen,
		tracker:        r.tracker,
		ip:             ip,
	}
	return func() { ch.Writer = orig }
}

// requestFacts returns the question type and the request's wire length —
// exact for a wire-born request, the library's estimate otherwise.
func requestFacts(req *middleware.Request) (qtype uint16, size int, ok bool) {
	// The wire branch first, and by Undecoded rather than by calling
	// Msg: Msg decodes on demand, so probing with it materialized every
	// request this middleware analyzed — reflex sits before the cache,
	// which put the whole byte path behind a decode whenever it was
	// enabled.
	if req.Undecoded() {
		return req.Qtype(), len(req.Raw()), true
	}
	m := req.Msg()
	if m == nil || len(m.Question) == 0 {
		return 0, 0, false
	}
	return m.Question[0].Qtype, m.Len(), true
}

// handleSuspicious handles a suspicious IP.
func (r *Reflex) handleSuspicious(ctx context.Context, ch *middleware.Chain, ip string, score float64) {
	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	q := req.Question[0]

	ReflexDetections.WithLabelValues(dns.TypeToString[q.Qtype]).Inc()

	// Learning mode - just log
	if r.cfg.ReflexLearningMode {
		zlog.Info("Reflex: suspicious IP (learning mode)",
			"ip", ip,
			"score", score,
			"query", q.Name,
			"type", dns.TypeToString[q.Qtype])
		ch.Next(ctx)
		return
	}

	// Block mode
	if r.cfg.ReflexBlockMode {
		zlog.Warn("Reflex: blocked suspicious IP",
			"ip", ip,
			"score", score,
			"query", q.Name,
			"type", dns.TypeToString[q.Qtype])

		ReflexBlocked.Inc()
		ch.CancelWithRcode(dns.RcodeRefused, false)
		return
	}

	// Monitor mode - just log
	zlog.Debug("Reflex: suspicious IP detected",
		"ip", ip,
		"score", score)
	ch.Next(ctx)
}

// cleanup runs periodic maintenance.
func (r *Reflex) cleanup() {
	defer r.wg.Done()

	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.tracker.Cleanup()
			ReflexTrackedIPs.Set(float64(r.tracker.Count()))
		case <-r.done:
			return
		}
	}
}

// Close shuts down the middleware.
func (r *Reflex) Close() error {
	close(r.done)
	r.wg.Wait()
	return nil
}

// getAmpFactor returns amplification factor for query type.
func getAmpFactor(qtype uint16) float64 {
	if f, ok := ampFactors[qtype]; ok {
		return f
	}
	return 1.0 // Default: no amplification concern
}

// responseWriter wraps ResponseWriter to track response sizes.
type responseWriter struct {
	middleware.ResponseWriter
	reqLen  int
	tracker *IPTracker
	ip      string
}

// Size forwards the response's wire length from the writer beneath. The
// embedded interface deliberately does not carry Size, so a wrapper has to
// pass it along or observers above fall back to decoding the response.
func (w *responseWriter) Size() int {
	return middleware.ResponseSize(w.ResponseWriter)
}

func (rw *responseWriter) WriteMsg(res *dns.Msg) error {
	// Record response size for amplification tracking
	if res != nil {
		rw.tracker.RecordResponse(rw.ip, rw.reqLen, res.Len())
	}
	return rw.ResponseWriter.WriteMsg(res)
}

// WireReady passes the byte path through: this layer only observes sizes, so
// its presence must not push a cache hit back onto the Msg path — which is
// what wrapping without these two methods did.
// BeginWire/CommitWire/AbortWire pass the body lease through; the commit
// flows through WriteWire so amplification tracking still records sizes.
func (rw *responseWriter) BeginWire(size, reserve int) []byte {
	if leaser, ok := rw.ResponseWriter.(middleware.WireBodyLeaser); ok {
		return leaser.BeginWire(size, reserve)
	}
	return nil
}

func (rw *responseWriter) CommitWire(body []byte, info middleware.WireInfo) error {
	return rw.WriteWire(body, info)
}

func (rw *responseWriter) AbortWire() {
	if leaser, ok := rw.ResponseWriter.(middleware.WireBodyLeaser); ok {
		leaser.AbortWire()
	}
}

func (rw *responseWriter) WireReady() (middleware.WireCapability, bool) {
	next, ok := rw.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.WireCapability{}, false
	}
	return next.WireReady()
}

// WriteWire records the amplification observation and forwards the bytes.
// len(body) is the response's true wire length at this layer — WriteMsg has
// to settle for res.Len(), an estimate that builds a compression dictionary
// to answer.
//
// The observation is recorded after the downstream write, and only if the
// chain did not decline: on ErrWireFallback the cache retakes the Msg path
// and WriteMsg records that serve, so counting here too would credit the
// source with the same response twice and inflate its amplification score.
// A terminal transport error still records — bytes left the process.
func (rw *responseWriter) WriteWire(body []byte, info middleware.WireInfo) error {
	next, ok := rw.ResponseWriter.(middleware.WireWriter)
	if !ok {
		return middleware.ErrWireFallback
	}
	size := len(body)
	err := next.WriteWire(body, info)
	if !errors.Is(err, middleware.ErrWireFallback) {
		rw.tracker.RecordResponse(rw.ip, rw.reqLen, size)
	}
	return err
}
