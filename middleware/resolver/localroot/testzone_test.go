package localroot

import (
	"crypto"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

// testRoot adapts roottest.Build for this package's tests: a miniature
// signed root — apex SOA/NS/DNSKEY/NSEC sealed by ZONEMD, a signed com.
// delegation, an unsigned org. delegation, in-zone glue — chained to one
// CSK whose DS is the trust anchor.
type testRoot struct {
	rrs     []dns.RR
	anchors []dns.RR
	serial  uint32
	key     *dns.DNSKEY
	priv    crypto.PrivateKey
}

func buildTestRoot(t *testing.T) *testRoot {
	t.Helper()
	z, err := roottest.Build(ComputeDigest)
	if err != nil {
		t.Fatalf("roottest.Build: %v", err)
	}
	return &testRoot{
		rrs:     z.RRs,
		anchors: z.Anchors,
		serial:  roottest.Serial,
		key:     z.Key,
		priv:    z.Priv,
	}
}

func rrsFromText(t *testing.T, lines ...string) []dns.RR {
	t.Helper()
	out := make([]dns.RR, 0, len(lines))
	for _, l := range lines {
		rr, err := dns.NewRR(l)
		if err != nil {
			t.Fatalf("test zone RR %q: %v", l, err)
		}
		out = append(out, rr)
	}
	return out
}

func TestVerifyZoneChain(t *testing.T) {
	root := buildTestRoot(t)

	t.Run("a sealed zone verifies against its anchor", func(t *testing.T) {
		if _, err := verifyZone(root.rrs, root.anchors); err != nil {
			t.Fatalf("verifyZone: %v", err)
		}
	})

	t.Run("a tampered record fails the digest", func(t *testing.T) {
		tampered := append([]dns.RR(nil), root.rrs...)
		for i, rr := range tampered {
			if a, ok := rr.(*dns.A); ok {
				evil := dns.Copy(a).(*dns.A)
				evil.A[3]++
				tampered[i] = evil
				break
			}
		}
		if _, err := verifyZone(tampered, root.anchors); err == nil {
			t.Fatal("a tampered glue record verified")
		}
	})

	t.Run("a foreign anchor refuses the chain", func(t *testing.T) {
		foreign := rrsFromText(t,
			". 172800 IN DS 999 13 2 0000000000000000000000000000000000000000000000000000000000000000",
		)
		if _, err := verifyZone(root.rrs, foreign); err == nil {
			t.Fatal("zone verified against an anchor it does not chain to")
		}
	})

	t.Run("no anchors means no verification", func(t *testing.T) {
		if _, err := verifyZone(root.rrs, nil); err == nil {
			t.Fatal("zone verified with no trust anchors at all")
		}
	})

	t.Run("a serial mismatch refuses", func(t *testing.T) {
		mangled := append([]dns.RR(nil), root.rrs...)
		for i, rr := range mangled {
			if z, ok := rr.(*dns.ZONEMD); ok {
				evil := dns.Copy(z).(*dns.ZONEMD)
				evil.Serial++
				mangled[i] = evil
			}
		}
		// The ZONEMD content changed, so its signature fails first — either
		// refusal is correct; what must not happen is acceptance.
		if _, err := verifyZone(mangled, root.anchors); err == nil {
			t.Fatal("a ZONEMD serial mismatch verified")
		}
	})

	t.Run("a stripped ZONEMD refuses", func(t *testing.T) {
		var stripped []dns.RR
		for _, rr := range root.rrs {
			if rr.Header().Rrtype == dns.TypeZONEMD {
				continue
			}
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeZONEMD {
				continue
			}
			stripped = append(stripped, rr)
		}
		if _, err := verifyZone(stripped, root.anchors); err == nil {
			t.Fatal("a zone with no ZONEMD verified")
		}
	})
}
