package resolver

import (
	"context"
	"errors"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
)

// Resolution failure metrics. Classified at the central handler
// error-return point so individual return sites stay clean. Closed
// label sets — every reason is pre-registered below so the dynamic
// path never hits a cold-create.
var (
	resolverFailures = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_resolver_failures_total",
		Help: "Recursive resolution failures by reason",
	}, []string{"reason"})

	resolverFailTimeout     = resolverFailures.Register("timeout")
	resolverFailNoReachable = resolverFailures.Register("no_reachable_auth")
	resolverFailMaxDepth    = resolverFailures.Register("max_depth")
	resolverFailNetwork     = resolverFailures.Register("network_error")
	resolverFailOther       = resolverFailures.Register("other")

	resolverDNSSECFailures = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_resolver_dnssec_failures_total",
		Help: "DNSSEC validation failures by reason",
	}, []string{"reason"})

	resolverDNSSECBogus      = resolverDNSSECFailures.Register("bogus")
	resolverDNSSECSigExpired = resolverDNSSECFailures.Register("sig_expired")
	resolverDNSSECSigNotYet  = resolverDNSSECFailures.Register("sig_not_yet_valid")
	resolverDNSSECKeyMissing = resolverDNSSECFailures.Register("dnskey_missing")
	resolverDNSSECSigMissing = resolverDNSSECFailures.Register("rrsig_missing")
	resolverDNSSECNSECMiss   = resolverDNSSECFailures.Register("nsec_missing")
	resolverDNSSECUnsupAlg   = resolverDNSSECFailures.Register("unsupported_algorithm")
	resolverDNSSECOther      = resolverDNSSECFailures.Register("other")

	// Circuit breaker transitions. No per-server label — in resolver
	// mode the auth-server set is unbounded (every zone's
	// nameservers). The aggregate trip/reset rate is the operator
	// signal; per-server diagnosis lives in the existing zlog lines
	// at the trip/reset sites.
	circuitBreakerTrips = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_circuit_breaker_trips_total",
		Help: "Times the resolver circuit breaker opened (5 consecutive failures)",
	})

	circuitBreakerResets = metric.NewCounter(nil, prometheus.CounterOpts{
		Name: "dns_circuit_breaker_resets_total",
		Help: "Times an open circuit breaker closed (cool-down expired or success observed)",
	})

	// Trust-anchor RFC 5011 lifecycle events. Keyed by transition
	// only — the per-keytag breakdown lives in the zlog lines next
	// to each increment. Operators alert on revoked/missing rates.
	trustAnchorLifecycle = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_trust_anchor_lifecycle_total",
		Help: "RFC 5011 trust-anchor lifecycle transitions",
	}, []string{"transition"})

	taNewPending  = trustAnchorLifecycle.Register("new_pending")
	taBecameValid = trustAnchorLifecycle.Register("became_valid")
	taRevoked     = trustAnchorLifecycle.Register("revoked")
	taMissing     = trustAnchorLifecycle.Register("missing")
	taReappeared  = trustAnchorLifecycle.Register("reappeared")
	taDeleted     = trustAnchorLifecycle.Register("deleted")
)

// classifyResolverErr increments the appropriate counter for a non-
// nil resolver error. Timeout is checked first since context errors
// don't carry an EDE code by themselves. DNSSEC-specific EDE codes
// route to the dedicated DNSSEC vector; the rest land in the
// generic failures vector. Sentinel errors that share
// ExtendedErrorCodeOther (errMaxDepth, errParentDetection) get
// distinguished via errors.Is.
func classifyResolverErr(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		resolverFailTimeout.Inc()
		return
	}

	code, _ := dnsutil.ErrorToEDE(err)
	switch code {
	case dns.ExtendedErrorCodeDNSBogus:
		resolverDNSSECBogus.Inc()
	case dns.ExtendedErrorCodeSignatureExpired:
		resolverDNSSECSigExpired.Inc()
	case dns.ExtendedErrorCodeSignatureNotYetValid:
		resolverDNSSECSigNotYet.Inc()
	case dns.ExtendedErrorCodeDNSKEYMissing:
		resolverDNSSECKeyMissing.Inc()
	case dns.ExtendedErrorCodeRRSIGsMissing:
		resolverDNSSECSigMissing.Inc()
	case dns.ExtendedErrorCodeNSECMissing:
		resolverDNSSECNSECMiss.Inc()
	case dns.ExtendedErrorCodeUnsupportedDNSKEYAlgorithm,
		dns.ExtendedErrorCodeUnsupportedDSDigestType:
		resolverDNSSECUnsupAlg.Inc()
	case dns.ExtendedErrorCodeNoZoneKeyBitSet,
		dns.ExtendedErrorCodeDNSSECIndeterminate:
		resolverDNSSECOther.Inc()
	case dns.ExtendedErrorCodeNoReachableAuthority:
		resolverFailNoReachable.Inc()
	case dns.ExtendedErrorCodeNetworkError:
		resolverFailNetwork.Inc()
	default:
		if errors.Is(err, errMaxDepth) || errors.Is(err, errParentDetection) {
			resolverFailMaxDepth.Inc()
		} else {
			resolverFailOther.Inc()
		}
	}
}
