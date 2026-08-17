package middleware

import (
	"testing"

	"github.com/miekg/dns"
)

// TestResolutionAttemptHashAllocatesNothing pins the tuple hash: folding,
// rooting, and framing all happen on the stack.
func TestResolutionAttemptHashAllocatesNothing(t *testing.T) {
	q := dns.Question{Name: "WWW.Some-Long-Example-Name.COM", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	if n := testing.AllocsPerRun(200, func() {
		_ = resolutionAttemptHash(q, "[2001:db8::1]:53", "udp")
	}); n != 0 {
		t.Fatalf("allocs = %v, want 0", n)
	}
}

// TestResolutionAttemptHashCanonicalEquivalence pins the folding rules the
// old string key got from dns.CanonicalName: case and rooting collapse,
// distinct names do not.
func TestResolutionAttemptHashCanonicalEquivalence(t *testing.T) {
	base := resolutionAttemptHash(dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, "192.0.2.1:53", "udp")
	for _, name := range []string{"WWW.Example.", "www.example", "WWW.EXAMPLE"} {
		if h := resolutionAttemptHash(dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}, "192.0.2.1:53", "udp"); h != base {
			t.Fatalf("%q must hash with its canonical spelling", name)
		}
	}
	for _, tc := range []struct {
		name      string
		qtype     uint16
		endpoint  string
		transport string
	}{
		{"www.example2.", dns.TypeA, "192.0.2.1:53", "udp"},
		{"www.example.", dns.TypeAAAA, "192.0.2.1:53", "udp"},
		{"www.example.", dns.TypeA, "192.0.2.2:53", "udp"},
		{"www.example.", dns.TypeA, "192.0.2.1:53", "tcp"},
	} {
		if h := resolutionAttemptHash(dns.Question{Name: tc.name, Qtype: tc.qtype, Qclass: dns.ClassINET}, tc.endpoint, tc.transport); h == base {
			t.Fatalf("distinct tuple %+v collided with the base tuple", tc)
		}
	}
}

// TestResolutionAttemptBeginFirstAllocation pins the admission cost: the
// store is the only allocation, even for an uppercase name the old key
// paid a CanonicalName copy for.
func TestResolutionAttemptBeginFirstAllocation(t *testing.T) {
	const runs = 300
	guards := make([]*ResolutionAttemptGuard, runs+1)
	for i := range guards {
		guards[i] = NewResolutionAttemptGuard()
	}
	q := dns.Question{Name: "WWW.Example.COM.", Qtype: dns.TypeA, Qclass: dns.ClassINET}

	i := 0
	if n := testing.AllocsPerRun(runs, func() {
		g := guards[i]
		i++
		if err := g.Begin(q, "192.0.2.1:53", "udp"); err != nil {
			t.Fatal(err)
		}
	}); n != 1 {
		t.Fatalf("allocs = %v, want exactly the store", n)
	}
}
