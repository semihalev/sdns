package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/middleware"
)

// TestWireChainMismatchNamesTheGate pins the attribution the skip counter
// reports. The counter exists to say which gate turns hits away from byte
// serving, so a gate credited to the wrong reason would point the next
// change at the wrong place.
func TestWireChainMismatchNamesTheGate(t *testing.T) {
	plain := NewCacheEntryWithKey(
		wireFastEntry(t, "gate.example.com.", dns.TypeA, false), time.Minute, 0, 1)
	signed := NewCacheEntryWithKey(
		wireFastEntry(t, "gate.example.com.", dns.TypeA, true), time.Minute, 0, 1)
	if plain == nil || signed == nil {
		t.Fatal("entries were not admitted")
	}

	cases := []struct {
		name       string
		entry      *CacheEntry
		capability middleware.WireCapability
		want       string
	}{
		{
			name:       "signed entry to a client without DO",
			entry:      signed,
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
