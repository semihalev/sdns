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
// So the trimmer only acts when the server has been quiescent across
// several consecutive samples — a long idle, not a gap between queries —
// respects a cooldown, runs as the only one of itself, and is never part
// of the shutdown path: it stops with the context and leaves the
// deadline to the drain.
const (
	trimSampleEvery = 30 * time.Second
	trimAfterIdle   = 3 // consecutive quiescent samples before a trim
	trimCooldown    = 10 * time.Minute
)

// memoryTrimmer is the capability a listener exposes when it parks
// slabs in an idle cache.
type memoryTrimmer interface {
	// TrimIdleMemory drops parked slabs and reports how many went.
	TrimIdleMemory() int
}

// trimLoop is started by Run when the configuration asks for it.
func (s *Server) trimLoop(ctx context.Context) {
	ticker := time.NewTicker(trimSampleEvery)
	defer ticker.Stop()

	idleSamples := 0
	var lastTrim time.Time

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if !s.Quiesced() {
			idleSamples = 0
			continue
		}
		idleSamples++
		if idleSamples < trimAfterIdle || time.Since(lastTrim) < trimCooldown {
			continue
		}
		idleSamples = 0
		lastTrim = time.Now()

		dropped := 0
		s.listenersMu.Lock()
		active := append([]Listener(nil), s.active...)
		s.listenersMu.Unlock()
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
