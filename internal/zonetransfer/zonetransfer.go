// Package zonetransfer holds the secondary-zone transfer primitives:
// strict AXFR over TCP, the SOA serial probe, RFC 1982 serial comparison,
// schedule jitter, and RFC 5936 duplicate normalization.
//
// It exists because two consumers need exactly these and nothing forces
// them to share a lifecycle: the hyperlocal root (which verifies with
// ZONEMD against the trust anchors and schedules around a signature
// horizon) and RPZ policy feeds (which verify nothing cryptographic and
// withdraw on SOA expire). The refresh loops stay with their owners.
// Each is welded to its own verification and withdrawal semantics, and
// what is shared is the part with one right answer: how a zone is pulled,
// probed, compared, and deduplicated.
package zonetransfer

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsclient"
)

var (
	// ErrShape is a transfer or probe whose stream is not a zone: wrong
	// ID, wrong rcode, a stream not bracketed by the apex SOA, or a
	// terminator that differs from the opener.
	ErrShape = errors.New("zonetransfer: transfer did not carry a zone")
	// ErrLimit is a stream that exceeded the caller's sanity bounds.
	ErrLimit = errors.New("zonetransfer: transfer exceeded sanity bounds")
)

// Limits bounds one transfer, so a hostile or broken source cannot feed
// an unbounded stream. The caller sizes them for its zone: the root is a
// couple of megabytes; a commercial policy feed can run to millions of
// records.
type Limits struct {
	MaxRecords int
	MaxBytes   int
}

// AXFR transfers zone from addr over TCP and returns its records, the
// closing duplicate apex SOA dropped. The transfer is bounded by ctx and
// lim; any structural surprise refuses the whole transfer. There is no
// partial acceptance of a zone copy.
func AXFR(ctx context.Context, addr, zone string, timeout time.Duration, lim Limits) ([]dns.RR, error) {
	zone = dns.CanonicalName(zone)

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
	req.SetAxfr(zone)

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
			return nil, ErrShape
		}
		for _, rr := range resp.Answer {
			isApexSOA := rr.Header().Rrtype == dns.TypeSOA &&
				dns.CanonicalName(rr.Header().Name) == zone
			if !sawFirst {
				if !isApexSOA {
					return nil, ErrShape
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
				// the inconsistency surfaces later as a verification
				// mismatch, blamed on verification.
				if !dns.IsDuplicate(rrs[0], rr) {
					return nil, ErrShape
				}
				// The closing duplicate: the zone is complete. Anything the
				// source appends after it is not part of the zone and is
				// left unread.
				return rrs, nil
			}
			total += dns.Len(rr)
			if len(rrs) >= lim.MaxRecords || total > lim.MaxBytes {
				return nil, ErrLimit
			}
			rrs = append(rrs, rr)
		}
	}
}

// ProbeSerial asks addr for zone's SOA over TCP and returns its serial.
// TCP deliberately: the probe talks to the same transfer hosts the AXFR
// will, so a host that cannot serve TCP is discovered at the probe.
func ProbeSerial(ctx context.Context, addr, zone string, timeout time.Duration) (uint32, error) {
	zone = dns.CanonicalName(zone)

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
	req.SetQuestion(zone, dns.TypeSOA)
	req.RecursionDesired = false

	if err := co.WriteMsg(req); err != nil {
		return 0, err
	}
	resp, err := co.ReadMsg()
	if err != nil {
		return 0, err
	}
	if resp.Id != req.Id || resp.Rcode != dns.RcodeSuccess {
		return 0, ErrShape
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok &&
			dns.CanonicalName(soa.Header().Name) == zone {
			return soa.Serial, nil
		}
	}
	return 0, ErrShape
}

// SerialNewer reports whether b is newer than a in RFC 1982 serial
// arithmetic (the SOA serial's number space).
func SerialNewer(a, b uint32) bool {
	return (b > a && b-a < 1<<31) || (b < a && a-b > 1<<31)
}

// Jitter spreads d by ±10% so a fleet restarted together does not probe
// the same source in the same second forever.
func Jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	spread := int64(d / 10)
	return d - time.Duration(spread) + time.Duration(rand.Int64N(2*spread+1)) //nolint:gosec // schedule jitter, not key material.
}

// rrKey identifies an RRset member for duplicate detection: everything RFC
// 8976 §3.3.1.1 counts as identity except the RDATA, which dns.IsDuplicate
// compares directly.
type rrKey struct {
	owner  string
	rtype  uint16
	rclass uint16
}

// NormalizeZone drops duplicate RRs from a received zone, keeping the first
// of each. RFC 5936 §2.2 requires an AXFR client to ignore duplicates, and
// RFC 8976 §3.3.1.1 fixes the identity as owner, class, type and RDATA, the
// TTL is not part of it.
//
// This runs once, before anything else reads the records, because every stage
// downstream counts them: a doubled record must not look to any consumer like
// a zone with two, whether the consumer is a digest, an index, or a policy
// rule that accumulates local data.
func NormalizeZone(rrs []dns.RR) []dns.RR {
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
			// duplicate is dropped, but its TTL still has a say, otherwise
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

// firstDuplicate returns the record in rrs that rr duplicates, or nil when
// it is new. Identity is owner, class, type and RDATA, dns.IsDuplicate
// excludes the TTL. The sets it searches are one owner's records of one
// type, small enough that a linear scan is the whole of it.
func firstDuplicate(rrs []dns.RR, rr dns.RR) dns.RR {
	for _, have := range rrs {
		if dns.IsDuplicate(have, rr) {
			return have
		}
	}
	return nil
}
