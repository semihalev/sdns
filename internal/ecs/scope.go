package ecs

import (
	"net/netip"

	"github.com/miekg/dns"
)

// ReadResponseScope extracts the SCOPE prefix from an authoritative
// server's response OPT, expressed as a netip.Prefix the cache can
// key on. Returns (invalid, false) when:
//
//   - the response has no OPT, or
//   - the OPT has no EDNS0_SUBNET, or
//   - the option's Address is missing / unparseable, or
//   - SourceScope == 0 (RFC 7871 §6: "the answer is suitable for the
//     entire address space", i.e. cache shared-key, not scoped).
//
// The returned prefix is built from the option's Address truncated
// to SourceScope bits — that's the slice of IP space the authority
// is asserting the answer covers. The caller (cache insert path)
// can hand that prefix to Policy.ClampScope before keying.
//
// Used by middleware/cache in Stage 2; lives here so middleware/edns
// and middleware/cache share one definition.
func ReadResponseScope(resp *dns.Msg) (netip.Prefix, bool) {
	if resp == nil {
		return netip.Prefix{}, false
	}
	opt := resp.IsEdns0()
	if opt == nil {
		return netip.Prefix{}, false
	}
	for _, o := range opt.Option {
		sub, ok := o.(*dns.EDNS0_SUBNET)
		if !ok {
			continue
		}
		if sub.SourceScope == 0 {
			// "Global" answer per §6 — no scoping wanted.
			return netip.Prefix{}, false
		}
		addr, ok := ipToAddr(sub.Address)
		if !ok {
			return netip.Prefix{}, false
		}
		// Family sanity: a response that says Family=1 with a 16-byte
		// non-mapped address (or vice versa) is malformed; refuse to
		// build a scope from it.
		switch sub.Family {
		case 1:
			if !addr.Is4() {
				return netip.Prefix{}, false
			}
		case 2:
			if !addr.Is6() {
				return netip.Prefix{}, false
			}
		default:
			return netip.Prefix{}, false
		}
		prefix, err := addr.Prefix(int(sub.SourceScope))
		if err != nil {
			return netip.Prefix{}, false
		}
		return prefix, true
	}
	return netip.Prefix{}, false
}
