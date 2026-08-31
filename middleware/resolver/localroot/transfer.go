package localroot

import (
	"context"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/zonetransfer"
)

// The transfer primitives live in internal/zonetransfer since the RPZ
// feeds needed the same ones; what stays here is the root's own sizing
// and the names the rest of this package (and its tests) call.
var errTransferShape = zonetransfer.ErrShape

// rootTransferLimits bounds a root transfer: the zone is a couple of
// megabytes and a few tens of thousands of records, and these caps are
// far above any real root.
var rootTransferLimits = zonetransfer.Limits{
	MaxRecords: 1 << 20,
	MaxBytes:   64 << 20,
}

// axfr transfers the root zone from addr; see zonetransfer.AXFR.
func axfr(ctx context.Context, addr string, timeout time.Duration) ([]dns.RR, error) {
	return zonetransfer.AXFR(ctx, addr, ".", timeout, rootTransferLimits)
}

// probeSerial asks addr for the root SOA; see zonetransfer.ProbeSerial.
func probeSerial(ctx context.Context, addr string, timeout time.Duration) (uint32, error) {
	return zonetransfer.ProbeSerial(ctx, addr, ".", timeout)
}

// normalizeZone deduplicates a received zone; see
// zonetransfer.NormalizeZone.
func normalizeZone(rrs []dns.RR) []dns.RR { return zonetransfer.NormalizeZone(rrs) }

// serialNewer is RFC 1982 serial comparison; see zonetransfer.SerialNewer.
func serialNewer(a, b uint32) bool { return zonetransfer.SerialNewer(a, b) }

// jitter spreads a schedule interval; see zonetransfer.Jitter.
func jitter(d time.Duration) time.Duration { return zonetransfer.Jitter(d) }
