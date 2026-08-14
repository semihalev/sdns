package server

import (
	"errors"
	"net"
	"os"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

var errDrainTimeout = errors.New("server: shutdown drain deadline exceeded")

// isClosedNetErr reports the socket-closed condition that ends a read loop
// during shutdown.
func isClosedNetErr(err error) bool {
	return errors.Is(err, net.ErrClosed)
}

// isAdmissionStopErr reports the conditions that end a UDP read loop:
// the socket is gone, or shutdown expired its read deadline to stop
// admission while leaving the send side open for the drain. A reader that
// treated the expired deadline as transient would spin instead of exit.
func isAdmissionStopErr(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrDeadlineExceeded)
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
	// tx_error counts replies the transport refused. The send happens
	// after the middleware has unwound, so this counter — not a WriteMsg
	// error — is where a failed datagram becomes visible.
	udpTXError = udpIngressDrops.Register("tx_error")
)
