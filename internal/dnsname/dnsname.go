// Package dnsname walks domain-name labels without allocating.
//
// The library answers every label question by materializing it: Split builds
// an index slice, SplitDomainName a string slice, and CompareDomainName two
// index slices, per call, for answers that are a handful of comparisons. In
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
// right and stopping at the first inequality, dns.CompareDomainName's
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

// Sub reports whether name sits at or below zone, dns.IsSubDomain's answer,
// which is CompareSuffix covering every label of the zone.
func Sub(zone, name string) bool {
	return CompareSuffix(zone, name) == dns.CountLabel(zone)
}

// Suffixes yields the start offset of every label in name, in order,
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

// CanonicalCompare orders a and b per RFC 4034 §6.3: the canonical DNS name
// order, labels compared right to left as the octets they decode to,
// ASCII-folded, with the name that runs out of labels first sorting first.
// It is the ordering every NSEC coverage proof stands on.
//
// The octets, not the spelling. A presentation label is an encoding, `\065`
// is the octet 0x41, the same label as `a`; `\.` inside a label is the octet
// 0x2E, which sorts before `0`, and the comparison this replaces ordered
// the escape text instead, so wire-equal names compared unequal and names
// around the escapes could invert. Every escape is decoded as it is read,
// exactly as the library's packer decodes it, wrap quirk included (see
// decodeOctet), and nothing is materialized. A dangling backslash, which
// no valid name contains, decodes as a literal one, keeping the order total
// for inputs only a hand can construct.
//
// The fold is ASCII, which is what the RFC's canonical form specifies. (The
// old implementation folded through strings.ToLower, whose non-ASCII case
// mappings have no business in DNS names.)
//
// Rooted and unrooted spellings compare equal: labels are read without
// their separators, so the trailing root dot contributes nothing.
//
// The walk is forward, in label lockstep after aligning the starts, and the
// verdict is the rightmost pair that differed, right-to-left order without
// offset arrays, so the frame stays flat instead of carrying two of them.
func CanonicalCompare(a, b string) int {
	// Identical spellings are equal names, and they are what a response
	// carries: one owner, spelled one way, on every record and signature
	// of an RRset. A byte comparison settles that case before the label
	// walk, which admission otherwise paid several times per response.
	if a == b {
		return 0
	}
	ca, cb := canonicalLabelCount(a), canonicalLabelCount(b)
	offA, offB := 0, 0
	for i := ca; i > cb; i-- {
		offA, _ = dns.NextLabel(a, offA)
	}
	for i := cb; i > ca; i-- {
		offB, _ = dns.NextLabel(b, offB)
	}

	// Rightmost difference wins: labels are compared left to right and the
	// last nonzero verdict kept, which is the same answer a right-to-left
	// walk stops at.
	verdict := 0
	for i := min(ca, cb); i > 0; i-- {
		var labelA, labelB string
		labelA, offA = canonicalLabel(a, offA, i == 1)
		labelB, offB = canonicalLabel(b, offB, i == 1)
		if c := compareDecodedFold(labelA, labelB); c != 0 {
			verdict = c
		}
	}
	if verdict != 0 {
		return verdict
	}
	switch {
	case ca < cb:
		return -1
	case ca > cb:
		return 1
	}
	return 0
}

// canonicalLabelCount is the label count CanonicalCompare walks: the
// library's, except that the empty string counts as the root, which is what
// rooting it first, as the old implementation did, made of it.
func canonicalLabelCount(name string) int {
	if name == "" || name == "." {
		return 0
	}
	return dns.CountLabel(name)
}

// canonicalLabel returns the label starting at off, without its separator,
// and the offset of the next one. The final label sheds a trailing root dot
// if it has one; NextLabel decided the boundary, so the dot before a
// returned offset is never an escaped one.
func canonicalLabel(name string, off int, last bool) (string, int) {
	if !last {
		next, _ := dns.NextLabel(name, off)
		return name[off : next-1], next
	}
	label := name[off:]
	if len(label) > 1 && label[len(label)-1] == '.' && !escapedTail(label, len(label)-1) {
		label = label[:len(label)-1]
	}
	return label, len(name)
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

// compareDecodedFold orders two presentation labels as the octet strings
// they decode to, ASCII-folded: RFC 4034 §6.3's within-label order.
func compareDecodedFold(a, b string) int {
	i, j := 0, 0
	for i < len(a) && j < len(b) {
		var octA, octB byte
		octA, i = decodeOctet(a, i)
		octB, j = decodeOctet(b, j)
		if octA >= 'A' && octA <= 'Z' {
			octA |= 'a' - 'A'
		}
		if octB >= 'A' && octB <= 'Z' {
			octB |= 'a' - 'A'
		}
		switch {
		case octA < octB:
			return -1
		case octA > octB:
			return 1
		}
	}
	switch {
	case i < len(a):
		return 1
	case j < len(b):
		return -1
	}
	return 0
}

// decodeOctet reads one octet of a presentation label: a plain byte, an
// escaped one (`\.`), or a decimal escape (`\046`). The decoding is the
// library's, quirk included: its dddToByte computes `\DDD` in byte
// arithmetic, so a value past 255 wraps modulo 256 rather than erroring,
// no valid name carries one, and matching the authoritative decoder is what
// keeps the order aligned with the wire for the names that do.
func decodeOctet(s string, i int) (byte, int) {
	c := s[i]
	if c != '\\' || i+1 >= len(s) {
		return c, i + 1
	}
	if isDigit(s[i+1]) && i+3 < len(s) && isDigit(s[i+2]) && isDigit(s[i+3]) {
		return (s[i+1]-'0')*100 + (s[i+2]-'0')*10 + (s[i+3] - '0'), i + 4
	}
	return s[i+1], i + 2
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

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

// AppendCanonicalKey appends the canonical identity of a presentation name
// to dst: each label as the octets it decodes to, ASCII-folded and
// length-prefixed, then the root. Two names get the same key exactly when
// CanonicalCompare orders them equal, escaped and plain spellings, rooted
// and unrooted, ASCII case, and a fold that is not the wire's never merges
// what the wire keeps apart: a Kelvin sign is not a k. For the places a
// comparison cannot serve, a map keyed by string(key).
func AppendCanonicalKey(dst []byte, name string) []byte {
	labels := canonicalLabelCount(name)
	off := 0
	for i := labels; i > 0; i-- {
		var label string
		label, off = canonicalLabel(name, off, i == 1)
		dst = append(dst, 0)
		at := len(dst) - 1
		n := 0
		for j := 0; j < len(label); {
			var oct byte
			oct, j = decodeOctet(label, j)
			if oct >= 'A' && oct <= 'Z' {
				oct |= 'a' - 'A'
			}
			dst = append(dst, oct)
			n++
		}
		// A wire label holds at most 63 octets; a hand-built name past 255
		// wraps, and only needs a key consistent with itself.
		dst[at] = byte(n) //nolint:gosec // G115 - see above
	}
	return append(dst, 0)
}
