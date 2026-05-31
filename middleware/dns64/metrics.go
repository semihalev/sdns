package dns64

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

var (
	// Synthesised counts AAAA records produced from A records.
	// Bumped once per client query that resulted in synthesis,
	// not per individual record — the metric tracks how often
	// DNS64 had to step in, not how many addresses were embedded.
	Synthesised = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns64_synthesised_total",
		Help: "Total client AAAA queries answered with synthesised records",
	})

	// Passthrough counts AAAA queries that flowed through DNS64
	// without synthesis, labelled by the reason. "aaaa_present"
	// is the steady-state happy path; the rest are exclusion
	// signals operators may want to monitor.
	Passthrough = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns64_passthrough_total",
		Help: "AAAA queries DNS64 left untouched, by reason",
	}, []string{"reason"})

	// Pre-resolved Passthrough handles — closed set; new reason
	// strings introduced in dns64.go must be added here too.
	passthroughInternal       = Passthrough.Register("internal")
	passthroughNoRD           = Passthrough.Register("no_rd")
	passthroughCDBit          = Passthrough.Register("cd_bit")
	passthroughClientExcluded = Passthrough.Register("client_excluded")
	passthroughZoneExcluded   = Passthrough.Register("zone_excluded")
	passthroughNXDomain       = Passthrough.Register("nxdomain")
	passthroughDNSSECFail     = Passthrough.Register("dnssec_fail")
	passthroughAAAAPresent    = Passthrough.Register("aaaa_present")
	passthroughAExcluded      = Passthrough.Register("a_excluded")

	// ALookupFailures counts secondary A-record lookups that did
	// not yield a usable result (SERVFAIL, no answer, etc.).
	// Reason labels are bounded to a small set so the cardinality
	// stays low.
	ALookupFailures = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns64_a_lookup_failures_total",
		Help: "Failures of the secondary A lookup issued during DNS64 synthesis",
	}, []string{"reason"})

	// Pre-resolved ALookupFailures handles. The "other" /
	// classifyQueryErr labels are also registered here so the
	// dynamic-label call site never hits a cold-create.
	aLookupQueryerError = ALookupFailures.Register("queryer_error")
	aLookupNilResponse  = ALookupFailures.Register("nil_response")
	aLookupServfail     = ALookupFailures.Register("servfail")
	aLookupNXDomain     = ALookupFailures.Register("nxdomain")
	aLookupOtherRcode   = ALookupFailures.Register("other_rcode")
	aLookupNoA          = ALookupFailures.Register("no_a")
	_                   = ALookupFailures.Register("no_response")
	_                   = ALookupFailures.Register("max_recursion")
	_                   = ALookupFailures.Register("other")

	// PTRTranslated counts ip6.arpa PTR queries DNS64 redirected
	// to their in-addr.arpa counterpart per RFC 6147 §5.3.1.
	PTRTranslated = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns64_ptr_translated_total",
		Help: "Total ip6.arpa PTR queries answered with a CNAME to in-addr.arpa",
	})
)
