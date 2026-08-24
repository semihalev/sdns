package localroot

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// The two example zones and their digests are RFC 8976 Appendix A verbatim.
// They pin the digest rules an implementation gets wrong first: apex ZONEMD
// excluded but a non-apex ZONEMD included, duplicates digested once,
// occluded data included, out-of-zone data excluded, owner and RDATA names
// canonicalized, and RRsets ordered by owner, type, then RDATA.

const rfc8976SimpleZone = `
$ORIGIN example.
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400  IN  NS      ns1
example.      86400  IN  NS      ns2
example.      86400  IN  ZONEMD  2018031900 1 1 c68090d90a7aed716bc459f9340e3d7c1370d4d24b7e2fc3a1ddc0b9a87153b9a9713b3c9ae5cc27777f98b8e730044c
ns1           3600   IN  A       203.0.113.63
ns2           3600   IN  AAAA    2001:db8::63
`

const rfc8976ComplexZone = `
$ORIGIN example.
example.      86400  IN  SOA     ns1 admin 2018031900 1800 900 604800 86400
example.      86400  IN  NS      ns1
example.      86400  IN  NS      ns2
example.      86400  IN  ZONEMD  2018031900 1 1 a3b69bad980a3504e1cffcb0fd6397f93848071c93151f552ae2f6b1711d4bd2d8b39808226d7b9db71e34b72077f8fe
ns1           3600   IN  A       203.0.113.63
NS2           3600   IN  AAAA    2001:db8::63
occluded.sub  7200   IN  TXT     "I'm occluded but must be digested"
sub           7200   IN  NS      ns1
duplicate     300    IN  TXT     "I must be digested just once"
duplicate     300    IN  TXT     "I must be digested just once"
foo.test.     555    IN  TXT     "out-of-zone data must be excluded"
UPPERCASE     3600   IN  TXT     "canonicalize uppercase owner names"
*             777    IN  PTR     dont-forget-about-wildcards
mail          3600   IN  MX      20 MAIL1
mail          3600   IN  MX      10 Mail2.Example.
sortme        3600   IN  AAAA    2001:db8::5:61
sortme        3600   IN  AAAA    2001:db8::3:62
sortme        3600   IN  AAAA    2001:db8::4:63
sortme        3600   IN  AAAA    2001:db8::1:65
sortme        3600   IN  AAAA    2001:db8::2:64
non-apex      900    IN  ZONEMD  2018031900 1 1 616c6c6f776564206275742069676e6f7265642e20616c6c6f776564206275742069676e6f7265642e20616c6c6f7765
`

func parseZoneText(t *testing.T, text string) []dns.RR {
	t.Helper()
	var rrs []dns.RR
	zp := dns.NewZoneParser(strings.NewReader(text), "example.", "rfc8976-appendix-a")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("zone parse: %v", err)
	}
	if len(rrs) == 0 {
		t.Fatal("zone parse yielded nothing")
	}
	return rrs
}

func zonemdDigest(t *testing.T, rrs []dns.RR) string {
	t.Helper()
	for _, rr := range rrs {
		if z, ok := rr.(*dns.ZONEMD); ok && dns.CanonicalName(z.Header().Name) == "example." {
			return strings.ToLower(z.Digest)
		}
	}
	t.Fatal("no apex ZONEMD in the vector")
	return ""
}

func TestComputeDigestRFC8976Vectors(t *testing.T) {
	for name, text := range map[string]string{
		"simple":  rfc8976SimpleZone,
		"complex": rfc8976ComplexZone,
	} {
		t.Run(name, func(t *testing.T) {
			rrs := parseZoneText(t, text)
			got, err := ComputeDigest(rrs, "example.")
			if err != nil {
				t.Fatalf("computeDigest: %v", err)
			}
			if want := zonemdDigest(t, rrs); hex.EncodeToString(got) != want {
				t.Fatalf("digest = %s, want RFC 8976's %s", hex.EncodeToString(got), want)
			}
		})
	}
}
