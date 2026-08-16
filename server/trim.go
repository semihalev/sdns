package server

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/semihalev/zlog/v2"
)

// Trim gives a burst's memory back to the operating system.
//
// The idle caches make it collectable — trim drops their references —
// but collectable is not returned: measured, a full burst released into
// the caches kept its resident set until an explicit collection, because
// the background scavenger returns freed pages on a timescale of
// minutes. FreeOSMemory does it at once, at the cost of one synchronous
// GC over the whole process. That cost is why trimming is opt-in and
// conservative: on a busy or big-memory server it buys nothing anyone
// needed, and on a single small core the pause lands on whatever is in
// flight.
//
// So the trimmer only acts on a genuinely idle window: every sample in
// it quiescent *and* the admission counters unmoved across it — an
// instantaneous Quiesced() can be true between two queries of steady
// light traffic, and a history cannot. It respects a cooldown, runs as
// the only one of itself, and is never part of the shutdown path: it
// stops with the context and leaves the deadline to the drain.
//
// One deliberate gap: per-connection stream buffers live in a sync.Pool
// (they are connection-lifetime state, bounded by connection churn), and
// a single collection moves them to the pool's victim generation rather
// than freeing them. They return on the following natural GC cycle;
// spending a second forced collection here to hurry ~14KB per recent
// connection was judged worse than the wait.
const (
	trimSampleEvery = 30 * time.Second
	trimAfterIdle   = 3 // consecutive idle samples before a trim
	trimCooldown    = 10 * time.Minute
)

// memoryTrimmer is the capability a listener exposes when it parks
// slabs in an idle cache.
type memoryTrimmer interface {
	// TrimIdleMemory drops parked slabs and reports how many went.
	TrimIdleMemory() int
	// AdmissionCount reports how many queries have ever been admitted;
	// the trimmer compares it across samples to prove a window carried
	// no traffic at all.
	AdmissionCount() uint64
}

// trimGate decides when an idle window is real. Separated from the loop
// so the decision — not the ticker — is what gets tested.
type trimGate struct {
	idleSamples  int
	lastAdmitted uint64
	lastTrim     time.Time
}

// observe records one sample and reports whether a trim should fire.
func (g *trimGate) observe(now time.Time, quiesced bool, admitted uint64) bool {
	if !quiesced || admitted != g.lastAdmitted {
		g.idleSamples = 0
		g.lastAdmitted = admitted
		return false
	}
	g.idleSamples++
	if g.idleSamples < trimAfterIdle || now.Sub(g.lastTrim) < trimCooldown {
		return false
	}
	g.idleSamples = 0
	g.lastTrim = now
	return true
}

// trimLoop is started by Run when the configuration asks for it.
func (s *Server) trimLoop(ctx context.Context) {
	ticker := time.NewTicker(trimSampleEvery)
	defer ticker.Stop()
	var gate trimGate

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		s.listenersMu.Lock()
		active := append([]Listener(nil), s.active...)
		s.listenersMu.Unlock()

		var admitted uint64
		for _, l := range active {
			if t, ok := l.(memoryTrimmer); ok {
				admitted += t.AdmissionCount()
			}
		}
		if !gate.observe(time.Now(), s.Quiesced(), admitted) {
			continue
		}

		dropped := 0
		for _, l := range active {
			if t, ok := l.(memoryTrimmer); ok {
				dropped += t.TrimIdleMemory()
			}
		}
		if dropped == 0 {
			continue
		}
		start := time.Now()
		debug.FreeOSMemory()
		zlog.Info("Idle memory trimmed", "slabs", dropped,
			"took", time.Since(start).String())
	}
}
