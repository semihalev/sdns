package dnsutil

import (
	"testing"

	"github.com/miekg/dns"
)

func TestFormatQuestion(t *testing.T) {
	for _, tc := range []struct {
		q    dns.Question
		want string
	}{
		{dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, "example.com. IN A"},
		{dns.Question{Name: "EXAMPLE.Com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, "example.com. IN AAAA"},
		{dns.Question{Name: ".", Qtype: dns.TypeNS, Qclass: dns.ClassCHAOS}, ". CH NS"},
	} {
		if got := FormatQuestion(tc.q); got != tc.want {
			t.Errorf("FormatQuestion(%+v) = %q, want %q", tc.q, got, tc.want)
		}
	}
}

var formatQuestionSink string

// TestFormatQuestionAllocsOnce pins the single-concatenation shape: an
// already-lowercase name costs exactly one allocation, the result string.
func TestFormatQuestionAllocsOnce(t *testing.T) {
	q := dns.Question{Name: "already.lower.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	allocs := testing.AllocsPerRun(100, func() {
		formatQuestionSink = FormatQuestion(q)
	})
	if allocs != 1 {
		t.Fatalf("FormatQuestion allocated %.0f times per call, want 1", allocs)
	}
}
