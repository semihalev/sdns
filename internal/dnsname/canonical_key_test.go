package dnsname

import "testing"

// TestAppendCanonicalKeyAgreesWithCanonicalCompare pins the key to the
// comparison: names the comparison orders equal share a key, names it keeps
// apart do not. Escaped and plain spellings, rooted and unrooted, ASCII
// case merge; a Kelvin sign, which a Unicode fold turns into k, stays a
// different name, as it is on the wire.
func TestAppendCanonicalKeyAgreesWithCanonicalCompare(t *testing.T) {
	key := func(name string) string {
		var buf [64]byte
		return string(AppendCanonicalKey(buf[:0], name))
	}
	for _, tc := range []struct {
		a, b string
		same bool
	}{
		{"target.example.", `t\097rget.example.`, true},
		{"k.example.", "k.example", true},
		{"K.EXAMPLE.", "k.example.", true},
		{"a\\.b.example.", "a.b.example.", false},
		{"K.example.", "k.example.", false},
		{".", "", true},
	} {
		if got := key(tc.a) == key(tc.b); got != tc.same {
			t.Errorf("%q vs %q: same key = %v, want %v", tc.a, tc.b, got, tc.same)
		}
		if got := CanonicalCompare(tc.a, tc.b) == 0; got != tc.same {
			t.Errorf("%q vs %q: CanonicalCompare equal = %v, want %v", tc.a, tc.b, got, tc.same)
		}
	}
}
