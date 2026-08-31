package rpz

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	rpzengine "github.com/semihalev/sdns/internal/rpz"
)

// The outcome label separates what acted from what would have: exactly one
// enforced count per acting query, everything else observed — shadow mode,
// disabled zones, and (in later phases) losers under precedence. Summing
// over outcome gives a zone's match rate in any mode, which is what makes
// a soak-then-flip comparable (design §5.5).
const (
	outcomeEnforced = "enforced"
	outcomeObserved = "observed"
)

var (
	actionTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rpz_action_total",
		Help: "RPZ matches under the winner-bounded counting semantic, by zone, trigger, action, and whether the match acted (enforced) or only would have (observed)",
	}, []string{"zone", "trigger", "action", "outcome"})

	zoneRules = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rpz_zone_rules",
		Help: "Compiled rules per policy zone and trigger type, set on load",
	}, []string{"zone", "trigger"})

	zoneRulesSkipped = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rpz_zone_rules_skipped",
		Help: "Records a zone load stepped over, by reason",
	}, []string{"zone", "reason"})

	reloadErrors = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "rpz_reload_errors_total",
		Help: "Zone loads or reloads that failed; the previous store keeps serving",
	}, []string{"zone"})

	zoneSerial = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "rpz_zone_serial",
		Help: "SOA serial of an AXFR-fed zone's installed copy; -1 for file-sourced zones and for a feed whose rules are withdrawn",
	}, []string{"zone"})
)

// countMatch runs on the match path only — the non-matching query touches
// no counter (design §5.11).
func countMatch(m rpzengine.ZoneMatch, outcome string) {
	actionTotal.WithLabelValues(m.Zone.Name, m.Trigger, m.Effective().String(), outcome).Inc()
}

// skipReasons is every reason the engine can count, so a reload publishes
// the full set — a reason that dropped to zero reads as zero, rather than
// keeping the previous generation's value on the board.
var skipReasons = []string{
	rpzengine.SkipTrigger,
	rpzengine.SkipOwnerEncoding,
	rpzengine.SkipUnknownAction,
	rpzengine.SkipNotActionData,
	rpzengine.SkipConflict,
	rpzengine.SkipOutOfZone,
	rpzengine.SkipApexData,
}

func publishZoneMetrics(z *rpzengine.Zone) {
	zoneRules.WithLabelValues(z.Name, rpzengine.TriggerQNAME).Set(float64(z.Rules - z.RulesClientIP))
	zoneRules.WithLabelValues(z.Name, rpzengine.TriggerClientIP).Set(float64(z.RulesClientIP))
	for _, reason := range skipReasons {
		zoneRulesSkipped.WithLabelValues(z.Name, reason).Set(float64(z.Skipped[reason]))
	}
}
