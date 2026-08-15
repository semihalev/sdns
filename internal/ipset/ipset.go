// Package ipset answers one question: is this address inside any of
// these CIDRs?
//
// It replaces a prefix-trie library that converted the address into a
// freshly allocated slice on every lookup. That allocation sat on the
// hottest path a resolver has — the access list runs before the cache,
// so every query paid it.
//
// A prefix is a contiguous range of addresses, so a set of prefixes is a
// set of ranges, and "is this address in one of them" is the classic
// stabbing query: sort the ranges by where they start, remember the
// furthest end seen so far, and one binary search answers it. Overlaps
// and nesting need no special handling, lookups touch a flat slice, and
// nothing allocates.
//
// A Set is built once at startup and read concurrently afterwards.
package ipset

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sort"
)

// BadEntry is a CIDR that would not parse, reported rather than fatal:
// a typo in one entry should not knock out the rest of a config.
type BadEntry struct {
	CIDR string
	Err  error
}

func (b BadEntry) Error() string { return fmt.Sprintf("%s: %s", b.CIDR, b.Err) }

// Set is a compiled list of prefixes. The zero value is an empty set,
// which contains nothing.
type Set struct {
	// Separated by family: a lookup only searches ranges that could
	// match, and an IPv6-heavy list costs an IPv4 client nothing.
	v4 []span
	v6 []span
}

// span is one prefix as an inclusive address range, plus the furthest
// end among every span up to and including it. That running maximum is
// what lets a single binary search answer the query: among the spans
// that begin at or before the address, one reaches past it exactly when
// the maximum does.
type span struct {
	lo, hi u128
	maxHi  u128
}

// u128 is an address as a number, wide enough for both families.
type u128 struct{ hi, lo uint64 }

func (a u128) lessEq(b u128) bool { return a.hi < b.hi || (a.hi == b.hi && a.lo <= b.lo) }

// New compiles cidrs into a Set, returning the entries it could not
// parse. Host bits are allowed and masked away, as net.ParseCIDR has
// always accepted them.
func New(cidrs []string) (*Set, []BadEntry) {
	s := new(Set)
	var bad []BadEntry
	for _, cidr := range cidrs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			bad = append(bad, BadEntry{CIDR: cidr, Err: err})
			continue
		}
		s.add(p)
	}
	s.compile()
	return s, bad
}

// NewFromPrefixes compiles already-parsed prefixes.
func NewFromPrefixes(prefixes []netip.Prefix) *Set {
	s := new(Set)
	for _, p := range prefixes {
		if p.IsValid() {
			s.add(p)
		}
	}
	s.compile()
	return s
}

func (s *Set) add(p netip.Prefix) {
	p = p.Masked()
	lo, hi := bounds(p)
	if p.Addr().Is4() {
		s.v4 = append(s.v4, span{lo: lo, hi: hi})
		return
	}
	s.v6 = append(s.v6, span{lo: lo, hi: hi})
}

func (s *Set) compile() {
	compile(s.v4)
	compile(s.v6)
}

func compile(spans []span) {
	sort.Slice(spans, func(i, j int) bool {
		if spans[i].lo.hi != spans[j].lo.hi {
			return spans[i].lo.hi < spans[j].lo.hi
		}
		return spans[i].lo.lo < spans[j].lo.lo
	})
	var max u128
	for i := range spans {
		if max.lessEq(spans[i].hi) {
			max = spans[i].hi
		}
		spans[i].maxHi = max
	}
}

// Len returns how many prefixes the set holds.
func (s *Set) Len() int { return len(s.v4) + len(s.v6) }

// Contains reports whether addr falls inside any prefix in the set.
//
// An IPv4-mapped IPv6 address is answered as the IPv4 address it
// carries: that is what a client behind a dual-stack socket looks like,
// and an operator who wrote an IPv4 CIDR means it to match them.
func (s *Set) Contains(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	if addr.Is4In6() {
		addr = addr.Unmap()
	}
	spans := s.v6
	if addr.Is4() {
		spans = s.v4
	}
	if len(spans) == 0 {
		return false
	}
	k := key(addr)
	// The last span that begins at or before the address. Written out
	// rather than handed to sort.Search: the closure that would take is
	// an allocation on the path this package exists to keep clean.
	i, j := 0, len(spans)
	for i < j {
		m := int(uint(i+j) >> 1)
		if spans[m].lo.lessEq(k) {
			i = m + 1
		} else {
			j = m
		}
	}
	if i == 0 {
		return false
	}
	return k.lessEq(spans[i-1].maxHi)
}

// ContainsIP is Contains for callers holding a net.IP. The conversion is
// a value copy — nothing escapes, nothing allocates.
func (s *Set) ContainsIP(ip net.IP) bool {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	return s.Contains(addr)
}

// key reads an address as a number.
func key(a netip.Addr) u128 {
	if a.Is4() {
		b := a.As4()
		return u128{lo: uint64(binary.BigEndian.Uint32(b[:]))}
	}
	b := a.As16()
	return u128{hi: binary.BigEndian.Uint64(b[0:8]), lo: binary.BigEndian.Uint64(b[8:16])}
}

// bounds returns the first and last address of a masked prefix.
func bounds(p netip.Prefix) (lo, hi u128) {
	lo = key(p.Addr())
	width := 128
	if p.Addr().Is4() {
		width = 32
	}
	host := width - p.Bits()
	if width == 32 || host < 64 {
		return lo, u128{hi: lo.hi, lo: lo.lo | ones(host)}
	}
	return lo, u128{hi: lo.hi | ones(host-64), lo: ^uint64(0)}
}

// ones returns n low bits set, saturating at both ends so the shift is
// always defined.
func ones(n int) uint64 {
	if n <= 0 {
		return 0
	}
	if n >= 64 {
		return ^uint64(0)
	}
	return 1<<uint(n) - 1
}
