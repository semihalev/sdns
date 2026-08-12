package cache

import (
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
)

// TestWireChainMismatchNamesTheGate pins the attribution the skip counter
// reports. The counter exists to say which gate turns hits away from byte
// serving, so a gate credited to the wrong reason would point the next
// change at the wrong place.
func TestWireChainMismatchNamesTheGate(t *testing.T) {
	signedMsg := wireFastEntry(t, "gate.example.com.", dns.TypeA, true)
	plain := NewCacheEntryWithKey(
		wireFastEntry(t, "gate.example.com.", dns.TypeA, false), time.Minute, 0, 1)
	signed := NewCacheEntryWithKey(signedMsg, time.Minute, 0, 1)
	if plain == nil || signed == nil {
		t.Fatal("entries were not admitted")
	}

	// An entry whose stripped body could not be built keeps the Msg path for
	// its DO=0 hits; the gate must still turn them away rather than serve
	// the stored, signed body.
	strippedless := func(tb testing.TB, msg *dns.Msg) *CacheEntry {
		tb.Helper()
		bare := NewCacheEntryWithKey(msg, time.Minute, 0, 1)
		if bare == nil {
			tb.Fatal("entry was not admitted")
			return nil
		}
		bare.stripped, bare.strippedServe = nil, 0
		return bare
	}

	cases := []struct {
		name       string
		entry      *CacheEntry
		capability middleware.WireCapability
		want       string
	}{
		{
			// Served from the stripped body, so nothing is turned away.
			name:       "signed entry to a client without DO",
			entry:      signed,
			capability: middleware.WireCapability{DO: false},
			want:       "",
		},
		{
			name:       "signed entry with no stripped body to a client without DO",
			entry:      strippedless(t, signedMsg),
			capability: middleware.WireCapability{DO: false},
			want:       "skip_dnssec",
		},
		{
			name:       "reply beyond the transport ceiling",
			entry:      plain,
			capability: middleware.WireCapability{DO: true, Reserve: 11, MaxSize: len(plain.wire) + 10},
			want:       "skip_size",
		},
		{
			name:       "signed entry to a client with DO",
			entry:      signed,
			capability: middleware.WireCapability{DO: true},
			want:       "",
		},
		{
			name:       "plain entry to a client without DO",
			entry:      plain,
			capability: middleware.WireCapability{DO: false},
			want:       "",
		},
	}

	named := map[*metric.Counter]string{
		wireSkipDNSSEC: "skip_dnssec",
		wireSkipSize:   "skip_size",
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mismatch := tc.entry.wireChainMismatch(tc.capability)
			got := ""
			if mismatch != nil {
				got = named[mismatch]
				if got == "" {
					t.Fatalf("mismatch reported an unnamed counter")
				}
			}
			if got != tc.want {
				t.Fatalf("mismatch = %q, want %q", got, tc.want)
			}
			// The boolean gate and the named one must never disagree: the
			// counter is derived from the same decision that routes the hit.
			if fits := tc.entry.wireFitsChain(tc.capability); fits != (mismatch == nil) {
				t.Fatalf("wireFitsChain = %v but mismatch = %v", fits, mismatch)
			}
		})
	}
}

// TestStrippedBodyCarriesNoDNSSEC pins what the stripped body is allowed to
// contain. It is what a client that did not ask for DNSSEC receives, so a
// signature surviving here would send DNSSEC records to a client that never
// asked — the exact leak the DO=0 gate exists to prevent.
func TestStrippedBodyCarriesNoDNSSEC(t *testing.T) {
	signedMsg := wireFastEntry(t, "strip.example.com.", dns.TypeA, true)
	entry := NewCacheEntryWithKey(signedMsg, time.Minute, 0, 1)
	if entry == nil {
		t.Fatal("entry was not admitted")
	}
	if entry.stripped == nil {
		t.Fatal("a signed entry was admitted without a stripped body")
	}

	decoded := new(dns.Msg)
	if err := decoded.Unpack(entry.stripped); err != nil {
		t.Fatalf("stripped body does not unpack: %v", err)
	}
	for _, section := range [][]dns.RR{decoded.Answer, decoded.Ns, decoded.Extra} {
		for _, rr := range section {
			switch rr.(type) {
			case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
				t.Fatalf("stripped body still carries %s", rr.Header().Name)
			}
		}
	}

	// It must also be everything the Msg path would have sent. The stored
	// body run through the same filter is that answer.
	reference := new(dns.Msg)
	if err := reference.Unpack(entry.wire); err != nil {
		t.Fatalf("stored body does not unpack: %v", err)
	}
	dnsutil.ClearDNSSEC(reference)
	if len(decoded.Answer) != len(reference.Answer) ||
		len(decoded.Ns) != len(reference.Ns) {
		t.Fatalf("stripped body holds %d/%d records, the Msg path would send %d/%d",
			len(decoded.Answer), len(decoded.Ns),
			len(reference.Answer), len(reference.Ns))
	}
	for i, rr := range decoded.Answer {
		if rr.String() != reference.Answer[i].String() {
			t.Fatalf("answer %d diverged\n stripped: %s\n      msg: %s",
				i, rr, reference.Answer[i])
		}
	}

	if entry.strippedServe&wireHasDNSSEC != 0 {
		t.Fatal("the stripped body is still marked as carrying DNSSEC")
	}
	t.Logf("stored %d bytes, stripped %d bytes (%.0f%%)",
		len(entry.wire), len(entry.stripped),
		100*float64(len(entry.stripped))/float64(len(entry.wire)))
}

// TestUnsignedEntryHasNoStrippedBody pins the other half: an entry with
// nothing to strip must not pay for a second body.
func TestUnsignedEntryHasNoStrippedBody(t *testing.T) {
	entry := NewCacheEntryWithKey(
		wireFastEntry(t, "plain.example.com.", dns.TypeA, false), time.Minute, 0, 1)
	if entry == nil {
		t.Fatal("entry was not admitted")
	}
	if entry.stripped != nil {
		t.Fatalf("an unsigned entry retained %d bytes it can never serve",
			len(entry.stripped))
	}
}

// BenchmarkAdmitSignedEntry measures what the stripped body costs where it
// is paid: admission, which happens on a cache miss — after a full recursion
// and validation, and once per entry rather than once per hit.
func BenchmarkAdmitSignedEntry(b *testing.B) {
	const qname = "signed.example.com."
	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.AuthenticatedData = true
	signature := strings.Repeat("A", 342) + "=="
	msg.Answer = append(msg.Answer,
		makeRR(qname+" 300 IN A 192.0.2.10"),
		makeRR(qname+" 300 IN A 192.0.2.11"),
		makeRR(qname+" 300 IN RRSIG A 8 3 300 20370101000000 20260101000000 7 example.com. "+signature),
	)

	b.ReportAllocs()
	for b.Loop() {
		if NewCacheEntryWithKey(msg, time.Minute, 0, 1) == nil {
			b.Fatal("entry was not admitted")
		}
	}
}
