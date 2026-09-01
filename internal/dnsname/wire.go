package dnsname

// This file renders uncompressed wire-form names into presentation form
// without heap allocation: the caller supplies the destination, typically a
// stack buffer. The escape mapping is byte-identical to miekg's
// UnpackDomainName, the special set {'.', ' ', '\'', '@', ';', '(', ')',
// '"', '\\'} is backslash-prefixed, bytes outside 0x20 to 0x7E become \DDD,
// which is the same contract internal/cache's wire key hasher already
// depends on. The parity test drives every byte value through both
// implementations.
//
// dns.UnpackDomainName is retired from SDNS's own paths in favor of these:
// it is allocation-friendly (its scratch stays on the stack; the result
// string is its only allocation), but a result string is one allocation
// more than a lookup needs. A key written into a stack buffer indexes a map
// with string(buf) for free, and that is how the hot paths stay at zero.

// maxWireNameOctets is the RFC 1035 name length bound in wire form.
const maxWireNameOctets = 255

// MaxPresentationLength bounds the presentation form of any legal wire
// name: every octet escaping to \DDD, plus label separators. Callers size
// stack buffers with it.
const MaxPresentationLength = 61*4 + 1 + 63*4 + 1 + 63*4 + 1 + 63*4 + 1

// isPresentationSpecial mirrors miekg's isDomainNameLabelSpecial.
func isPresentationSpecial(b byte) bool {
	switch b {
	case '.', ' ', '\'', '@', ';', '(', ')', '"', '\\':
		return true
	}
	return false
}

// appendWireName is the one walker behind the exported variants. fold
// lowercases ASCII A to Z (escape digits and specials are never A to Z, so
// folding the escaped form equals escaping the folded form). rooted keeps
// the trailing dot and renders the root name as "."; unrooted drops the
// trailing dot and renders the root name empty, the lookup-key spelling.
//
// A name that is not a plain, exactly-consumed uncompressed name refuses;
// dst comes back truncated to its original length in that case (a grown
// append may have moved it to a new backing array, so callers must use the
// returned slice, never the original).
//
// A non-nil offs additionally records each label's start offset within the
// appended region; the int return is how many entries were filled, and a
// name with more labels than offs holds refuses.
func appendWireName(dst, wire []byte, fold, rooted bool, offs []int) ([]byte, int, bool) {
	if len(wire) == 0 || len(wire) > maxWireNameOctets {
		return dst, 0, false
	}
	mark := len(dst)
	n := 0
	off := 0
	for {
		if off >= len(wire) {
			return dst[:mark], 0, false
		}
		c := int(wire[off])
		off++
		if c == 0 {
			break
		}
		if c&0xC0 != 0 || off+c > len(wire) {
			return dst[:mark], 0, false
		}
		if offs != nil {
			if n == len(offs) {
				return dst[:mark], 0, false
			}
			offs[n] = len(dst) - mark
		}
		n++
		for _, b := range wire[off : off+c] {
			switch {
			case isPresentationSpecial(b):
				dst = append(dst, '\\', b)
			case b < ' ' || b > '~':
				dst = append(dst, '\\', '0'+b/100, '0'+b/10%10, '0'+b%10)
			default:
				if fold && b >= 'A' && b <= 'Z' {
					b += 'a' - 'A'
				}
				dst = append(dst, b)
			}
		}
		dst = append(dst, '.')
		off += c
	}
	if off != len(wire) {
		return dst[:mark], 0, false
	}
	switch {
	case len(dst) == mark:
		if rooted {
			dst = append(dst, '.')
		}
	case !rooted:
		dst = dst[:len(dst)-1]
	}
	return dst, n, true
}

// AppendPresentation appends the presentation form of an uncompressed
// wire-form name to dst, byte-identical to what dns.UnpackDomainName
// returns for the same bytes, trailing dot included, case preserved.
func AppendPresentation(dst, wire []byte) ([]byte, bool) {
	out, _, ok := appendWireName(dst, wire, false, true, nil)
	return out, ok
}

// AppendFoldedKey appends the lookup-key form: the presentation form with
// ASCII A to Z lowered and no trailing dot (the root name comes back empty).
// This is the spelling hostsfile keys its database with and domain metrics
// tracks, so a stack-buffered key indexes those maps with zero allocation.
func AppendFoldedKey(dst, wire []byte) ([]byte, bool) {
	out, _, ok := appendWireName(dst, wire, true, false, nil)
	return out, ok
}

// MaxLabels bounds the label count of any legal wire name: every label
// needs a length byte plus one octet inside the 255-octet wire bound.
const MaxLabels = 127

// AppendCanonicalLabels appends the canonical spelling, the presentation
// form with ASCII A to Z lowered and the trailing dot kept, dns.CanonicalName's
// answer, and records where each label starts inside the appended region.
// offs needs capacity MaxLabels; the returned count says how many entries
// were filled, and its contents are undefined on refusal. Suffix matching
// against canonical zone keys then indexes a map with canon[offs[i]:]
// without ever building a string, a recipe that assumes an empty dst,
// since the offsets are relative to the appended region, not the slice.
func AppendCanonicalLabels(dst, wire []byte, offs []int) ([]byte, int, bool) {
	return appendWireName(dst, wire, true, true, offs)
}

// WireLabelCount returns the number of labels in an uncompressed wire-form
// name, dns.CountLabel's answer without the string. The root name has
// zero.
func WireLabelCount(wire []byte) (int, bool) {
	if len(wire) == 0 || len(wire) > maxWireNameOctets {
		return 0, false
	}
	n, off := 0, 0
	for {
		if off >= len(wire) {
			return 0, false
		}
		c := int(wire[off])
		off++
		if c == 0 {
			break
		}
		if c&0xC0 != 0 || off+c > len(wire) {
			return 0, false
		}
		n++
		off += c
	}
	if off != len(wire) {
		return 0, false
	}
	return n, true
}
