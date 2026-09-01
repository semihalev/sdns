package rpz

import (
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/rpz"
	"github.com/semihalev/zlog/v2"
)

// reloadDebounce coalesces the event burst a feed replacement produces
// into one reload, the hostsfile cadence.
const reloadDebounce = 100 * time.Millisecond

// watch follows hostsfile's proven shape: the parent directory is
// watched and events are filtered to the zone's file, because a watch on
// the file itself dies with the old inode when the feed is replaced by
// atomic rename — which is exactly how feeds are pushed.
func (r *RPZ) watch() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		zlog.Warn("RPZ file watcher failed; zones will not auto-reload", "error", err.Error())
		return
	}

	dirs := make(map[string]bool)
	for _, zc := range r.zones {
		if zc.File == "" {
			// AXFR-fed zones have no file to watch; their feed loop owns
			// their freshness.
			continue
		}
		dir := filepath.Dir(zc.File)
		if dirs[dir] {
			continue
		}
		dirs[dir] = true
		if err := watcher.Add(dir); err != nil {
			zlog.Warn("RPZ watch failed for a zone directory", "dir", dir, "error", err.Error())
		}
	}

	go r.watchLoop(watcher)
}

func (r *RPZ) watchLoop(watcher *fsnotify.Watcher) {
	timers := make(map[int]*time.Timer)
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) == 0 {
				continue
			}
			for i := range r.zones {
				// Empty File is an AXFR feed; Clean("") is "." and must
				// never match an event.
				if r.zones[i].File == "" || filepath.Clean(event.Name) != filepath.Clean(r.zones[i].File) {
					continue
				}
				idx := i
				if t := timers[idx]; t != nil {
					t.Stop()
				}
				timers[idx] = time.AfterFunc(reloadDebounce, func() { r.reload(idx) })
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			zlog.Warn("RPZ watcher error", "error", err.Error())
		}
	}
}

// reload re-reads one zone and swaps a store carrying it. A failed parse
// keeps the old zone serving and says so — a bad push never leaves the
// resolver unprotected or half-loaded. The parse runs outside the lock,
// so a slow file never stalls an AXFR feed's install — which opens a
// race the sequence below closes: a slow parse of the *previous* push
// finishing after a fast parse of the next one must not write the old
// generation back over the new. Each reload claims the zone's sequence
// before parsing, and the commit refuses a claim that is no longer the
// latest.
func (r *RPZ) reload(idx int) {
	seq := r.reloadSeq[idx].Add(1)
	zc := r.zones[idx]
	policy, _ := rpz.ParseOverride(zc.Policy)
	target := ""
	if zc.Cname != "" {
		target = dns.CanonicalName(zc.Cname)
	}
	z, err := rpz.LoadZoneFile(zc.Name, zc.File, policy, target, zc.Origin)
	if err != nil {
		reloadErrors.WithLabelValues(zc.Name).Inc()
		zlog.Warn("RPZ zone reload failed; the previous rules keep serving", "zone", zc.Name, "error", err.Error())
		return
	}
	// The same zero-rule semantic the config gate enforces: a push that
	// parses but compiles nothing — SOA/NS only, or every record skipped —
	// would silently strip a working policy. That is a broken push, not a
	// smaller feed, and the previous generation keeps serving.
	if z.Rules == 0 {
		reloadErrors.WithLabelValues(zc.Name).Inc()
		zlog.Warn("RPZ zone reload compiled no rules; the previous rules keep serving",
			"zone", zc.Name, "skipped", len(z.Skipped))
		return
	}

	if !r.commitReload(idx, seq, z) {
		zlog.Debug("RPZ reload superseded by a newer push", "zone", zc.Name)
		return
	}

	zlog.Info("RPZ zone reloaded", "zone", zc.Name, "rules", z.Rules, "skipped", len(z.Skipped))
}

// commitReload installs a parsed zone only if seq is still the latest
// claim for idx — the check and the swap share the lock, so a superseded
// parse cannot slip between them. The gauges are published inside the
// same critical section: published after it, a commit that finished
// first could write its counts over a newer generation's.
func (r *RPZ) commitReload(idx int, seq uint64, z *rpz.Zone) bool {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	if r.reloadSeq[idx].Load() != seq {
		return false
	}
	r.swapZoneLocked(idx, z)
	publishZoneMetrics(z)
	return true
}

// swapZone publishes a new compiled zone at idx: a copied slice, a fresh
// immutable store, one atomic swap. reloadMu serializes writers — the
// file watcher and the AXFR feeds share it — so two swaps cannot build
// from the same old slice and lose one another.
func (r *RPZ) swapZone(idx int, z *rpz.Zone) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()
	r.swapZoneLocked(idx, z)
}

func (r *RPZ) swapZoneLocked(idx int, z *rpz.Zone) {
	old := r.store.Load()
	zones := make([]*rpz.Zone, len(old.Zones))
	copy(zones, old.Zones)
	zones[idx] = z
	r.publishStore(&rpz.Store{Zones: zones})
}
