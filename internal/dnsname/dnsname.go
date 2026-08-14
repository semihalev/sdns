// Package dnsname walks domain-name labels without allocating.
//
// The library answers every label question by materializing it: Split builds
// an index slice, SplitDomainName a string slice, and CompareDomainName two
// index slices — per call, for answers that are a handful of comparisons. In
// the field the two of them were 4.3% of every object the resolver
// allocated. The functions here give the same answers out of a single
// forward walk, using the library's own NextLabel for boundary and escape
// handling, so there is no second implementation of `\.` to get wrong.
package dnsname

import (
	"iter"

	"github.com/miekg/dns"
)

// CompareSuffix returns how many labels a and b share, counted from the
// right and stopping at the first inequality — dns.CompareDomainName's
// answer without its two index slices.
//
// The library's exact comparison is preserved: ASCII case folding only, the
// final label read to the end of the string (so a rooted and an unrooted
// spelling of the same name do not match on it), and every other label read
// through its separating dot.
func CompareSuffix(a, b string) int {
	if a == "." || b == "." {
		return 0
	}
	ca, cb := dns.CountLabel(a), dns.CountLabel(b)
	offA, offB := 0, 0
	for ; ca > cb; ca-- {
		offA, _ = dns.NextLabel(a, offA)
	}
	for ; cb > ca; cb-- {
		offB, _ = dns.NextLabel(b, offB)
	}

	// With the starts aligned, one forward pass in lockstep. The shared
	// suffix is the trailing run of equal labels, so the counter resets on
	// every mismatch and holds the run's length at the end.
	n := 0
	for ; ca > 1; ca-- {
		nextA, _ := dns.NextLabel(a, offA)
		nextB, _ := dns.NextLabel(b, offB)
		if equalFold(a[offA:nextA], b[offB:nextB]) {
			n++
		} else {
			n = 0
		}
		offA, offB = nextA, nextB
	}
	if ca == 1 && equalFold(a[offA:], b[offB:]) {
		return n + 1
	}
	return 0
}

// Sub reports whether name sits at or below zone — dns.IsSubDomain's answer,
// which is CompareSuffix covering every label of the zone.
func Sub(zone, name string) bool {
	return CompareSuffix(zone, name) == dns.CountLabel(zone)
}

// Suffixes yields the start offset of every label in name, in order —
// dns.Split's answer as an iteration instead of a slice. The root name
// yields nothing, exactly as Split returns nil for it.
func Suffixes(name string) iter.Seq[int] {
	return func(yield func(int) bool) {
		if name == "." {
			return
		}
		off := 0
		for {
			if !yield(off) {
				return
			}
			next, end := dns.NextLabel(name, off)
			if end {
				return
			}
			off = next
		}
	}
}

// maxWireLabels is the most labels a name that fits DNS wire format can
// carry: 127 one-octet labels in a 255-octet name. A presentation string
// long enough to exceed it cannot have come off the wire; CanonicalCompare
// falls back to an allocating walk for those rather than answer wrongly.
const maxWireLabels = 127

// CanonicalCompare orders a and b per RFC 4034 §6.1: labels compared
// right to left, case-insensitively, with the name that runs out of labels
// first sorting first. It is the ordering every NSEC coverage proof stands
// on, and the previous implementation lowercased, rooted and split both
// names to compute it.
//
// The fold is ASCII, which is both what the RFC's canonical form specifies
// and what the library's own comparisons do. (The implementation this
// replaces folded through strings.ToLower, whose non-ASCII case mappings
// have no business in DNS names; names that reach this function come from
// packed messages, whose presentation form escapes non-ASCII bytes.)
//
// A second deliberate divergence, also unreachable from a packed message: a
// raw multi-byte rune directly before a backslash run at the end of a name
// trips a rune-versus-byte miscount in the library's IsFqdn, which the old
// implementation inherited through Fqdn — it declared such names unrooted,
// rooted them a second time, and compared a phantom empty label. This walk
// counts bytes and does not.
//
// Rooted and unrooted spellings compare equal — the labels are read without
// their separators, so the trailing root dot contributes nothing. The
// previous implementation rooted both names first for the same effect.
func CanonicalCompare(a, b string) int {
	// A name ending in an unescaped backslash is a quirk the fuzzer found:
	// the rooting dot the old implementation appended lands behind the
	// backslash and becomes a literal, changing the final label. No packed
	// message can produce the shape — a literal backslash presents as \\ —
	// but parity is the contract, so it keeps the old walk.
	if escapedTail(a, len(a)) || escapedTail(b, len(b)) {
		return canonicalCompareSlow(a, b)
	}

	var bufA, bufB [maxWireLabels]int
	na, okA := labelOffsets(a, &bufA)
	nb, okB := labelOffsets(b, &bufB)
	if !okA || !okB {
		// Beyond any wire-legal name: correctness over thrift. The rooted
		// canonical walk the old implementation did, for the inputs only a
		// hand can construct.
		return canonicalCompareSlow(a, b)
	}

	i, j := na-1, nb-1
	for i >= 0 && j >= 0 {
		if c := compareFold(labelAt(a, &bufA, na, i), labelAt(b, &bufB, nb, j)); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case na < nb:
		return -1
	case na > nb:
		return 1
	}
	return 0
}

// canonicalCompareSlow is CanonicalCompare for names carrying more labels
// than wire format allows: the allocating split, kept off the ordinary path.
func canonicalCompareSlow(a, b string) int {
	al := dns.SplitDomainName(dns.Fqdn(a))
	bl := dns.SplitDomainName(dns.Fqdn(b))
	i, j := len(al)-1, len(bl)-1
	for i >= 0 && j >= 0 {
		if c := compareFold(al[i], bl[j]); c != 0 {
			return c
		}
		i--
		j--
	}
	switch {
	case len(al) < len(bl):
		return -1
	case len(al) > len(bl):
		return 1
	}
	return 0
}

// labelOffsets writes the label start offsets of name into buf, reporting
// how many and whether they fit. The buffer travels as an array pointer that
// is never retained, which is what keeps it on the caller's stack.
func labelOffsets(name string, buf *[maxWireLabels]int) (n int, ok bool) {
	if name == "." || name == "" {
		return 0, true
	}
	off := 0
	for {
		if n == len(buf) {
			return n, false
		}
		buf[n] = off
		n++
		next, end := dns.NextLabel(name, off)
		if end {
			return n, true
		}
		off = next
	}
}

// labelAt returns the i-th of n labels without its separator: the trailing
// dot for a middle label, the root dot for a rooted final one.
func labelAt(name string, buf *[maxWireLabels]int, n, i int) string {
	start := buf[i]
	if i+1 < n {
		return name[start : buf[i+1]-1]
	}
	label := name[start:]
	if len(label) > 0 && label[len(label)-1] == '.' && !escapedTail(name, len(name)-1) {
		return label[:len(label)-1]
	}
	return label
}

// escapedTail reports whether the byte at i is escaped: preceded by an odd
// number of backslashes.
func escapedTail(s string, i int) bool {
	backslashes := 0
	for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
		backslashes++
	}
	return backslashes%2 == 1
}

// equalFold is the library's own label equality: same length, ASCII case
// folded, nothing else.
func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := len(a) - 1; i >= 0; i-- {
		ai, bi := a[i], b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}

// compareFold orders two labels byte-wise under the same ASCII fold.
func compareFold(a, b string) int {
	n := min(len(a), len(b))
	for i := range n {
		ai, bi := a[i], b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		switch {
		case ai < bi:
			return -1
		case ai > bi:
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}
