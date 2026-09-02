package dnsutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestSiblingIdentityIsTheWireName is the canonical-identity matrix for
// sibling grouping. Two spellings of one wire name, escaped and plain,
// rooted and unrooted, ASCII case, are one RRset, so a live signature
// under either covers an expired one under the other. A Kelvin sign is not a
// k: the Unicode fold says so, the wire does not, and a live signature under
// the one must not rescue an expired RRset under the other. Owner and signer
// both, on the inline path and past it through the map, in both wire orders.
func TestSiblingIdentityIsTheWireName(t *testing.T) {
	now := time.Now()
	sig := func(owner, signer string, until time.Duration) dns.RR {
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			TypeCovered: dns.TypeA, OrigTtl: 3600, SignerName: signer,
			Inception:  uint32(now.Add(-2 * time.Hour).Unix()), //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
			Expiration: uint32(now.Add(until).Unix()),          //nolint:gosec // test timestamp is in DNSSEC's uint32 era.
		}
	}
	a := func(owner string) dns.RR {
		return &dns.A{Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}, A: []byte{192, 0, 2, 1}}
	}
	// filler puts n distinct signed RRsets ahead of the pair, so the pair
	// is grouped past the inline capacity, through the map.
	filler := func(n int) []dns.RR {
		var rrs []dns.RR
		for i := range n {
			owner := fmt.Sprintf("f%d.example.", i)
			rrs = append(rrs, a(owner), sig(owner, "example.", time.Hour))
		}
		return rrs
	}

	type spelling struct {
		name     string
		a, b     string
		siblings bool
	}
	owners := []spelling{
		{"escaped and plain", "target.example.", `t\097rget.example.`, true},
		{"rooted and unrooted", "k.example.", "k.example", true},
		{"ASCII case", "K.EXAMPLE.", "k.example.", true},
		{"Kelvin sign and k", "K.example.", "k.example.", false},
	}
	signers := []spelling{
		{"ASCII case", "EXAMPLE.", "example.", true},
		{"escaped and plain", `ex\097mple.`, "example.", true},
		{"Kelvin sign and k", "Keep.example.", "keep.example.", false},
	}

	check := func(t *testing.T, records []dns.RR, siblings bool) {
		t.Helper()
		msg := new(dns.Msg)
		msg.SetQuestion("k.example.", dns.TypeA)
		msg.Answer = records
		if got := HasExpiredSignatures(msg, now); got == siblings {
			t.Errorf("HasExpiredSignatures = %v, want %v", got, !siblings)
		}
		ttl := CalculateCacheTTL(msg, TypeSuccess)
		if siblings && ttl < 59*time.Minute {
			t.Errorf("lifetime %v, want the live sibling's hour", ttl)
		}
		if !siblings && ttl != 0 {
			t.Errorf("lifetime %v, want nothing: an RRset is uncovered", ttl)
		}
	}

	for _, path := range []struct {
		name string
		pad  int
	}{{"inline", 0}, {"past the inline capacity", signedRRsetInline + 1}} {
		for _, o := range owners {
			for _, order := range []string{"expired first", "live first"} {
				t.Run(fmt.Sprintf("owner %s, %s, %s", o.name, path.name, order), func(t *testing.T) {
					expired, live := sig(o.a, "example.", -time.Hour), sig(o.b, "example.", time.Hour)
					pair := []dns.RR{a(o.a), expired, live}
					if order == "live first" {
						pair = []dns.RR{a(o.a), live, expired}
					}
					check(t, append(filler(path.pad), pair...), o.siblings)
				})
			}
		}
		for _, s := range signers {
			for _, order := range []string{"expired first", "live first"} {
				t.Run(fmt.Sprintf("signer %s, %s, %s", s.name, path.name, order), func(t *testing.T) {
					expired, live := sig("k.example.", s.a, -time.Hour), sig("k.example.", s.b, time.Hour)
					pair := []dns.RR{a("k.example."), expired, live}
					if order == "live first" {
						pair = []dns.RR{a("k.example."), live, expired}
					}
					check(t, append(filler(path.pad), pair...), s.siblings)
				})
			}
		}
	}
}
