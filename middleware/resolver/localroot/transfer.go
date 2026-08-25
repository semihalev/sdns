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
				// RFC 5936 §2.2: the stream begins and ends with the same
				// SOA record. A terminator that differs from the opener is a
				// source whose zone moved under the transfer, so the records
				// in between belong to no single version of it. Refusing
				// here fails over to the next source and names the fault at
				// the transfer; without the check the stream is accepted and
				// the inconsistency surfaces later as a digest mismatch,
				// blamed on verification.
				if !dns.IsDuplicate(rrs[0], rr) {
					return nil, errTransferShape
				}
				// The closing duplicate: the zone is complete. Anything the
				// source appends after it is not part of the zone and is
				// left unread.
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

// rrKey identifies an RRset member for duplicate detection: everything RFC
// 8976 §3.3.1.1 counts as identity except the RDATA, which dns.IsDuplicate
// compares directly.
type rrKey struct {
	owner  string
	rtype  uint16
	rclass uint16
}

// normalizeZone drops duplicate RRs from a received zone, keeping the first
// of each. RFC 5936 §2.2 requires an AXFR client to ignore duplicates, and
// RFC 8976 §3.3.1.1 fixes the identity as owner, class, type and RDATA — the
// TTL is not part of it.
//
// This runs once, before anything else reads the records, because every stage
// downstream counts them: the apex cardinality bound, the ZONEMD scheme/hash
// tuple check, the digest, and the index. A source that sends one record
// twice must not look to any of them like a zone with two. Left to the tuple
// check in particular, a doubled ZONEMD RR reads as a repeated tuple and
// refuses a zone RFC 5936 says should simply have been deduplicated.
func normalizeZone(rrs []dns.RR) []dns.RR {
	seen := make(map[rrKey][]dns.RR, len(rrs))
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		hdr := rr.Header()
		key := rrKey{
			owner:  dns.CanonicalName(hdr.Name),
			rtype:  hdr.Rrtype,
			rclass: hdr.Class,
		}
		if kept := firstDuplicate(seen[key], rr); kept != nil {
			// RFC 2181 §5.2: a receiver holding records of one RRset with
			// differing TTLs treats them as if all carried the lowest. The
			// duplicate is dropped, but its TTL still has a say — otherwise
			// the surviving record's lifetime depends on which copy the
			// source happened to send first.
			if rr.Header().Ttl < kept.Header().Ttl {
				kept.Header().Ttl = rr.Header().Ttl
			}
			continue
		}
		// Copied, because the TTL above is rewritten in place and the caller
		// still owns the records it handed us.
		rr = dns.Copy(rr)
		seen[key] = append(seen[key], rr)
		out = append(out, rr)
	}
	return out
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
