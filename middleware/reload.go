package middleware

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/zlog/v2"
)

// Reloader is a handler that applies some configuration keys while it
// runs. A reload asks it to prepare only when one of its keys changed.
//
// PrepareReload builds everything the new settings need, reading files
// included, and changes nothing a query can see. commit publishes them and
// cannot fail; it is run only once every owner of a changed key has
// prepared, so a refusal anywhere leaves every handler as it was.
type Reloader interface {
	ReloadKeys() []string
	PrepareReload(cfg *config.Config) (commit func(), err error)
}

// Reload outcomes, also the outcome label of dns_config_reloads_total.
const (
	ReloadApplied       = "applied"
	ReloadRestartNeeded = "restart_needed"
	ReloadUnchanged     = "unchanged"
	ReloadRejected      = "rejected"
)

// ReloadResult is what one reload did.
type ReloadResult struct {
	Outcome string
	Applied []string // changed keys now in effect
	Restart []string // keys that differ from what the server started with and no running handler applies
	Err     error    // why the file was refused, for ReloadRejected
}

// loglevelKey is applied by the reload itself: the logger is no handler's.
const loglevelKey = "loglevel"

var (
	configReloads = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_config_reloads_total",
		Help: "Configuration reloads by outcome",
	}, []string{"outcome"})
	reloadsByOutcome = map[string]*metric.Counter{
		ReloadApplied:       configReloads.Register(ReloadApplied),
		ReloadRestartNeeded: configReloads.Register(ReloadRestartNeeded),
		ReloadUnchanged:     configReloads.Register(ReloadUnchanged),
		ReloadRejected:      configReloads.Register(ReloadRejected),
	}
)

// reloads holds the two configurations a reload compares against: started
// is what the handlers were built from, where the keys no handler applies
// stay until a restart, and applied is the last file a reload accepted.
// The mutex also runs reloads one at a time.
var reloads struct {
	sync.Mutex
	started *config.Config
	applied *config.Config
}

// Reload reads the configuration at path again and applies what can
// change while the server runs. The file passes the gate startup uses,
// with unknown keys refused, before anything changes; a refused file, or
// an owner refusing its settings, leaves everything as it was. Reloads run
// one at a time, each comparing against the last.
func Reload(path string) ReloadResult {
	reloads.Lock()
	defer reloads.Unlock()

	r := reload(path)
	reloadsByOutcome[r.Outcome].Inc()
	return r
}

func reload(path string) ReloadResult {
	p := globalPipeline.Load()
	if p == nil || reloads.applied == nil {
		return ReloadResult{Outcome: ReloadRejected, Err: errors.New("server is not set up")}
	}
	running, started := reloads.applied, reloads.started

	// What Load probed or generated is the server's, from startup: a value
	// an earlier file named and a later one dropped is not in effect.
	next, err := config.Parse(path, func() bool { return started.IPv6Access })
	if err != nil {
		return ReloadResult{Outcome: ReloadRejected, Err: err}
	}
	if keys := next.UndecodedKeys(); len(keys) > 0 {
		return ReloadResult{Outcome: ReloadRejected,
			Err: fmt.Errorf("unknown keys (a typo, or settings this version no longer has): %s", strings.Join(keys, ", "))}
	}

	next.Inherit(started)

	owners := map[string][]Reloader{}
	var order []Reloader
	for _, h := range p.Handlers() {
		if rl, ok := h.(Reloader); ok {
			order = append(order, rl)
			for _, key := range rl.ReloadKeys() {
				owners[key] = append(owners[key], rl)
			}
		}
	}
	live := func(key string) bool { return key == loglevelKey || len(owners[key]) > 0 }

	var result ReloadResult
	for _, key := range config.ChangedKeys(running, next) {
		if live(key) {
			result.Applied = append(result.Applied, key)
		}
	}
	for _, key := range config.ChangedKeys(started, next) {
		if !live(key) {
			result.Restart = append(result.Restart, key)
		}
	}

	// Every owner of a changed key prepares before any commits.
	asked := map[Reloader]bool{}
	for _, key := range result.Applied {
		for _, rl := range owners[key] {
			asked[rl] = true
		}
	}
	var commits []func()
	for _, rl := range order {
		if !asked[rl] {
			continue
		}
		commit, err := rl.PrepareReload(next)
		if err != nil {
			return ReloadResult{Outcome: ReloadRejected, Err: err}
		}
		commits = append(commits, commit)
	}

	var level zlog.Level
	if slices.Contains(result.Applied, loglevelKey) {
		lvl, ok := next.LogVerbosity()
		if !ok {
			return ReloadResult{Outcome: ReloadRejected, Err: fmt.Errorf("loglevel = %q: unknown", next.LogLevel)}
		}
		level = lvl
	}

	for _, commit := range commits {
		commit()
	}
	if slices.Contains(result.Applied, loglevelKey) {
		zlog.SetLevel(level)
	}

	// The next reload compares live keys against this file. Keys that need
	// a restart are compared against started, so they are reported until
	// the server restarts or the file goes back.
	reloads.applied = next

	switch {
	case len(result.Restart) > 0:
		result.Outcome = ReloadRestartNeeded
	case len(result.Applied) > 0:
		result.Outcome = ReloadApplied
	default:
		result.Outcome = ReloadUnchanged
	}
	return result
}
