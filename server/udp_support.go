package server

import (
	"errors"
	"net"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

var errDrainTimeout = errors.New("server: shutdown drain deadline exceeded")

// isClosedNetErr reports the socket-closed condition that ends a read loop
// during shutdown.
func isClosedNetErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// Ingress drop accounting with pre-resolved handles: the vec's label
// lookup never runs on the serve path.
var (
	udpIngressDrops = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_udp_ingress_drops_total",
		Help: "UDP packets dropped before the handler, by reason",
	}, []string{"reason"})

	udpDropFull      = udpIngressDrops.Register("full")
	udpDropQueue     = udpIngressDrops.Register("queue")
	udpDropTrunc     = udpIngressDrops.Register("trunc")
	udpDropCtrunc    = udpIngressDrops.Register("ctrunc")
	udpDropMalformed = udpIngressDrops.Register("malformed")
	udpDropIgnored   = udpIngressDrops.Register("ignored")
	udpDropError     = udpIngressDrops.Register("error")
	udpDropPanic     = udpIngressDrops.Register("panic")
)
