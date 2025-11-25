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

// ServeDNS processes queries for amplification attack detection.
func (r *Reflex) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	// Skip internal/loopback/TCP (can't spoof TCP)
	if w.Internal() || w.RemoteIP() == nil || w.RemoteIP().IsLoopback() {
		ch.Next(ctx)
		return
	}

	// Only analyze UDP - TCP can't be spoofed
	if w.Proto() == "tcp" {
		// TCP connection proves IP is real - improve reputation
		r.tracker.RecordTCP(w.RemoteIP().String())
		ch.Next(ctx)
		return
	}

	if len(req.Question) == 0 {
		ch.Next(ctx)
		return
	}

	q := req.Question[0]
	ip := w.RemoteIP().String()

	// Calculate amplification potential
	ampFactor := getAmpFactor(q.Qtype)

	// Record this query
	score := r.tracker.RecordQuery(ip, q.Qtype, ampFactor, req.Len())

	// Check if IP exceeds threshold
	threshold := r.threshold()
	if score >= threshold {
		r.handleSuspicious(ctx, ch, ip, score)
		return
	}

	// Wrap response writer to track response size
	rw := &responseWriter{
		ResponseWriter: w,
		request:        req,
		tracker:        r.tracker,
		ip:             ip,
	}
	ch.Writer = rw

	ch.Next(ctx)
}

// handleSuspicious handles a suspicious IP.
func (r *Reflex) handleSuspicious(ctx context.Context, ch *middleware.Chain, ip string, score float64) {
	req := ch.Request
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
	request *dns.Msg
	tracker *IPTracker
	ip      string
}

func (rw *responseWriter) WriteMsg(res *dns.Msg) error {
	// Record response size for amplification tracking
	if res != nil {
		rw.tracker.RecordResponse(rw.ip, rw.request.Len(), res.Len())
	}
	return rw.ResponseWriter.WriteMsg(res)
}
