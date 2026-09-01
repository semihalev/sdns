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

	// udpOverflowServed counts jobs served on their own goroutine because
	// no worker was free. It is the signal that the pool is too small for
	// the shape of the traffic, a resolver serving misses spends most of
	// its time here, and that is fine; a server that is supposed to be
	// serving hits should see it near zero.
	udpOverflow = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_udp_ingress_overflow_total",
		Help: "UDP queries served outside the fixed worker pool",
	}, []string{"kind"})
	udpOverflowServed = udpOverflow.Register("served")

	// udpInline splits the reader fast path from the ring: "served" is a
	// query that finished on its reader, reply on the cycle's transmit
	// batch, no worker wake, and "handoff" is one the inline pass
	// admitted and guarded but a worker had to finish.
	udpInline = metric.NewCounterVec(nil, prometheus.CounterOpts{ //nolint:unused // Linux batch path
		Name: "dns_udp_inline_total",
		Help: "UDP queries attempted on the reader's inline fast path, by outcome",
	}, []string{"outcome"})
	udpInlineServed  = udpInline.Register("served")  //nolint:unused // Linux batch path
	udpInlineHandoff = udpInline.Register("handoff") //nolint:unused // Linux batch path

	udpDropFull      = udpIngressDrops.Register("full")
	udpDropTrunc     = udpIngressDrops.Register("trunc")
	udpDropCtrunc    = udpIngressDrops.Register("ctrunc")
	udpDropMalformed = udpIngressDrops.Register("malformed")
	udpDropIgnored   = udpIngressDrops.Register("ignored")
	udpDropError     = udpIngressDrops.Register("error")
	udpDropPanic     = udpIngressDrops.Register("panic")
	// tx_error counts replies the transport refused. The send happens
	// after the middleware has unwound, so this counter, not a WriteMsg
	// error, is where a failed datagram becomes visible.
	udpTXError = udpIngressDrops.Register("tx_error")
)
