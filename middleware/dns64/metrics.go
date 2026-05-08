package dns64

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Synthesised counts AAAA records produced from A records.
	// Bumped once per client query that resulted in synthesis,
	// not per individual record — the metric tracks how often
	// DNS64 had to step in, not how many addresses were embedded.
	Synthesised = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dns64_synthesised_total",
			Help: "Total client AAAA queries answered with synthesised records",
		},
	)

	// Passthrough counts AAAA queries that flowed through DNS64
	// without synthesis, labelled by the reason. "aaaa_present"
	// is the steady-state happy path; the rest are exclusion
	// signals operators may want to monitor.
	Passthrough = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns64_passthrough_total",
			Help: "AAAA queries DNS64 left untouched, by reason",
		},
		[]string{"reason"},
	)

	// ALookupFailures counts secondary A-record lookups that did
	// not yield a usable result (SERVFAIL, no answer, etc.).
	// Reason labels are bounded to a small set so the cardinality
	// stays low.
	ALookupFailures = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns64_a_lookup_failures_total",
			Help: "Failures of the secondary A lookup issued during DNS64 synthesis",
		},
		[]string{"reason"},
	)

	// PTRTranslated counts ip6.arpa PTR queries DNS64 redirected
	// to their in-addr.arpa counterpart per RFC 6147 §5.3.1.
	PTRTranslated = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "dns64_ptr_translated_total",
			Help: "Total ip6.arpa PTR queries answered with a CNAME to in-addr.arpa",
		},
	)
)
