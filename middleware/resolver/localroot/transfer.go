package localroot

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
)

var (
	errTransferShape = errors.New("localroot: transfer did not carry a zone")
	errTransferLimit = errors.New("localroot: transfer exceeded sanity bounds")
)

// Transfer sanity bounds: the root zone is a couple of megabytes and a few
// tens of thousands of records. These caps exist so a hostile or broken
// source cannot feed an unbounded stream; they are far above any real root.
const (
	maxTransferRecords = 1 << 20
	maxTransferBytes   = 64 << 20
)

// axfr transfers the root zone from addr over TCP and returns its records,
// the closing duplicate apex SOA dropped. The transfer is bounded by ctx and
// the sanity caps; any structural surprise refuses the whole transfer —
// there is no partial acceptance of a zone copy.
func axfr(ctx context.Context, addr string, timeout time.Duration) ([]dns.RR, error) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	co := &dnsclient.Conn{Conn: raw}
	defer func() { _ = co.Close() }()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = raw.SetDeadline(deadline)

	req := new(dns.Msg)
	req.SetAxfr(".")

	if err := co.WriteMsg(req); err != nil {
		return nil, err
	}

	var (
		rrs      []dns.RR
		sawFirst bool
		total    int
	)
	for {
		resp, err := co.ReadMsg()
		if err != nil {
			return nil, err
		}
		if resp.Id != req.Id || resp.Rcode != dns.RcodeSuccess {
			return nil, errTransferShape
		}
		for _, rr := range resp.Answer {
			isApexSOA := rr.Header().Rrtype == dns.TypeSOA &&
				dns.CanonicalName(rr.Header().Name) == "."
			if !sawFirst {
				if !isApexSOA {
					return nil, errTransferShape
				}
				sawFirst = true
				rrs = append(rrs, rr)
				continue
			}
			if isApexSOA {
				// The closing duplicate: the zone is complete.
				return rrs, nil
			}
			total += dns.Len(rr)
			if len(rrs) >= maxTransferRecords || total > maxTransferBytes {
				return nil, errTransferLimit
			}
			rrs = append(rrs, rr)
		}
	}
}

// probeSerial asks addr for the root SOA over TCP and returns its serial.
// TCP deliberately: the probe talks to the same transfer hosts the AXFR
// will, so a host that cannot serve TCP is discovered at the probe.
func probeSerial(ctx context.Context, addr string, timeout time.Duration) (uint32, error) {
	d := net.Dialer{Timeout: timeout}
	raw, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return 0, err
	}
	co := &dnsclient.Conn{Conn: raw}
	defer func() { _ = co.Close() }()

	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = raw.SetDeadline(deadline)

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeSOA)
	req.RecursionDesired = false

	if err := co.WriteMsg(req); err != nil {
		return 0, err
	}
	resp, err := co.ReadMsg()
	if err != nil {
		return 0, err
	}
	if resp.Id != req.Id || resp.Rcode != dns.RcodeSuccess {
		return 0, errTransferShape
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok &&
			dns.CanonicalName(soa.Header().Name) == "." {
			return soa.Serial, nil
		}
	}
	return 0, errTransferShape
}
