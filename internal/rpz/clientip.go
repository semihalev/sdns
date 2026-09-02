package rpz

import (
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// The CLIENT-IP trigger encodes an address block as an owner name under
// rpz-client-ip (draft §4.1.1): "prefix.B4.B3.B2.B1" for IPv4, octets
// reversed, IN-ADDR.ARPA style, and "prefix.W8...W1" for IPv6, the
// 16-bit hextets reversed, with a single "zz" label standing for a run of
// zero fields.
//
// The two families stay in SEPARATE tables, deliberately. Folding IPv4
// into the ::ffff/96 corner of one 128-bit space read well and was wrong
// twice over: a short IPv6 prefix, ::/0 above all, would swallow every
// IPv4 client, applying a rule the feed wrote for one family to the
// other; and an IPv6 ::ffff:0:0/96 rule collided with IPv4 0.0.0.0/0 in
// the same slot. An encoding names its family, and the family is part of
// what the rule means.

// ipLPM is the action-carrying longest-prefix-match structure the design
// calls for (§5.3). internal/ipset cannot serve here: its Contains answers
// only a bool and it coalesces overlapping prefixes, while policy needs
// the matched rule back and overlapping prefixes kept distinct.
//
// Shape: one map of masked addresses per prefix length actually present,
// walked longest-first. The walk is bounded by the feed's distinct
// lengths, not by us, the adversarial all-lengths benchmark beside this
// file is the exit criterion that keeps the shape honest.
type ipLPM struct {
	// lens holds the prefix lengths present, sorted descending, so the
	// first hit on the walk is the longest match (precedence rule 4).
	lens   []int
	tables []map[netip.Addr]*Rule
}

// insert files a rule under its masked prefix. The bool reports whether
// the slot was free; a second rule at the same prefix is the caller's
// conflict to count. A table holds one family; the caller routes.
func (l *ipLPM) insert(p netip.Prefix, r *Rule) bool {
	masked := p.Masked().Addr()
	for i, n := range l.lens {
		if n != p.Bits() {
			continue
		}
		if _, taken := l.tables[i][masked]; taken {
			return false
		}
		l.tables[i][masked] = r
		return true
	}
	l.lens = append(l.lens, p.Bits())
	l.tables = append(l.tables, map[netip.Addr]*Rule{masked: r})
	// Load-time only; the sort keeps the query walk longest-first.
	sort.Sort(sort.Reverse(byLen{l}))
	return true
}

type byLen struct{ l *ipLPM }

func (b byLen) Len() int           { return len(b.l.lens) }
func (b byLen) Less(i, j int) bool { return b.l.lens[i] < b.l.lens[j] }
func (b byLen) Swap(i, j int) {
	b.l.lens[i], b.l.lens[j] = b.l.lens[j], b.l.lens[i]
	b.l.tables[i], b.l.tables[j] = b.l.tables[j], b.l.tables[i]
}

// lookupExact returns the rule filed under exactly this prefix, for the
// load-time merge/conflict decision.
func (l *ipLPM) lookupExact(p netip.Prefix) *Rule {
	if l == nil {
		return nil
	}
	masked := p.Masked().Addr()
	for i, n := range l.lens {
		if n == p.Bits() {
			return l.tables[i][masked]
		}
	}
	return nil
}

// lookup returns the longest-prefix rule containing addr, with the
// matched prefix length, or nil. addr must be in the table's own family
// form (CanonicalClient's output). Zero allocations: prefix masking is
// value math and the map is keyed by a comparable value.
func (l *ipLPM) lookup(addr netip.Addr) (*Rule, int) {
	if l == nil {
		return nil, 0
	}
	for i, bits := range l.lens {
		p := netip.PrefixFrom(addr, bits)
		if r, ok := l.tables[i][p.Masked().Addr()]; ok {
			return r, bits
		}
	}
	return nil, 0
}

// CanonicalClient is the query-time twin of the rule-side encoding: the
// client's address in its family's native form. Unmap matters. A
// transport may hand an IPv4 client over as ::ffff:a.b.c.d, and that
// spelling must meet the IPv4 rules, not the IPv6 ones.
func CanonicalClient(a netip.Addr) netip.Addr { return a.Unmap() }

// parseClientIPOwner decodes the owner labels ahead of the rpz-client-ip
// marker into a 128-bit-space prefix. enc is the relative owner with the
// marker stripped, e.g. "24.0.2.0.192" or "128.1.zz.db8.2001". ok is
// false for an encoding the draft does not describe, counted by the
// caller as SkipOwnerEncoding, never a load failure.
//
// Host bits below the prefix are masked rather than refused: feeds vary
// in whether they write the network address exactly, and the rule the
// operator meant is the block either way.
func parseClientIPOwner(enc string) (netip.Prefix, bool) {
	labels := strings.Split(enc, ".")
	if len(labels) < 2 {
		return netip.Prefix{}, false
	}
	bits, err := strconv.Atoi(labels[0])
	if err != nil || bits < 0 {
		return netip.Prefix{}, false
	}
	labels = labels[1:]

	// IPv4: exactly four decimal octet labels, reversed. The prefix
	// stays in its own family. The family is part of what a rule means.
	if len(labels) == 4 && isV4Octets(labels) {
		if bits > 32 {
			return netip.Prefix{}, false
		}
		var b [4]byte
		for i, s := range labels {
			// ParseUint's 8-bit cap makes the byte conversion's bound
			// local and provable, isV4Octets already guaranteed it, but
			// a guarantee an analyzer cannot see is one a reader has to
			// chase too.
			v, err := strconv.ParseUint(s, 10, 8)
			if err != nil {
				return netip.Prefix{}, false
			}
			b[3-i] = byte(v)
		}
		return netip.PrefixFrom(netip.AddrFrom4(b), bits), true
	}

	// IPv6: up to eight hextet labels, reversed, with one optional "zz"
	// standing for the run of zero fields that makes the count come out
	// to eight.
	if bits > 128 || len(labels) > 8 {
		return netip.Prefix{}, false
	}
	fields := make([]uint16, 0, 8)
	zzAt := -1
	for i, s := range labels {
		if s == "zz" {
			if zzAt >= 0 {
				return netip.Prefix{}, false
			}
			zzAt = i
			continue
		}
		v, err := strconv.ParseUint(s, 16, 16)
		if err != nil || len(s) == 0 || len(s) > 4 {
			return netip.Prefix{}, false
		}
		fields = append(fields, uint16(v))
	}
	switch {
	case zzAt < 0 && len(fields) != 8:
		return netip.Prefix{}, false
	case zzAt >= 0 && len(fields) >= 8:
		return netip.Prefix{}, false
	}

	// Labels run W8..W1, the address's fields reversed, and zz expands
	// in place to whatever count restores eight.
	full := make([]uint16, 0, 8)
	zero := 8 - len(fields)
	fi := 0
	for i := 0; i < len(labels); i++ {
		if i == zzAt {
			for range zero {
				full = append(full, 0)
			}
			continue
		}
		full = append(full, fields[fi])
		fi++
	}

	var b [16]byte
	for i, w := range full {
		// full[0] is W8, the address's last field. The high byte of a
		// uint16 cannot exceed 255, and the low-byte truncation is the
		// point of the expression.
		b[14-2*i] = byte(w >> 8) //nolint:gosec // G115 - see above
		b[15-2*i] = byte(w)      //nolint:gosec // G115 - deliberate low-byte truncation
	}
	return netip.PrefixFrom(netip.AddrFrom16(b), bits), true
}

func isV4Octets(labels []string) bool {
	for _, s := range labels {
		v, err := strconv.Atoi(s)
		if err != nil || v < 0 || v > 255 || (len(s) > 1 && s[0] == '0') {
			return false
		}
	}
	return true
}
