package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

// listenerErrors counts listener Serve loops that exited with a
// non-nil error. Bumped per protocol so operators can tell whether
// UDP is degrading independently from TLS or DoH. Bounded label set
// — the value is l.Proto() which is one of udp/tcp/tls/doh/doh3/doq.
var (
	listenerErrors = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_listener_errors_total",
		Help: "Listener Serve loops that exited with an error, by transport",
	}, []string{"proto"})

	listenerErrUDP  = listenerErrors.Register("udp")
	listenerErrTCP  = listenerErrors.Register("tcp")
	listenerErrTLS  = listenerErrors.Register("tls")
	listenerErrDoH  = listenerErrors.Register("doh")
	listenerErrDoH3 = listenerErrors.Register("doh3")
	listenerErrDoQ  = listenerErrors.Register("doq")
)

// recordListenerErr maps a Listener.Proto() string to the matching
// pre-resolved counter. Unknown protocols fall through to the cold
// WithLabelValues path so the metric stays correct even if a new
// listener type lands without a corresponding handle here.
func recordListenerErr(proto string) {
	switch proto {
	case "udp":
		listenerErrUDP.Inc()
	case "tcp":
		listenerErrTCP.Inc()
	case "tls":
		listenerErrTLS.Inc()
	case "doh":
		listenerErrDoH.Inc()
	case "doh3":
		listenerErrDoH3.Inc()
	case "doq":
		listenerErrDoQ.Inc()
	default:
		listenerErrors.WithLabelValues(proto).Inc()
	}
}
