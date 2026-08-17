package as112

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// AS112 type.
type AS112 struct {
	zones map[string]bool
}

// New return a new middleware.
func New(cfg *config.Config) *AS112 {
	a := &AS112{zones: defaultZones}

	if len(cfg.EmptyZones) > 0 {
		zones := make(map[string]bool)

		for _, zone := range cfg.EmptyZones {
			if a.Match(zone, dns.TypeSOA) == rootzone {
				zlog.Error("Empty zone doesn't match in default empty zones, check your config!", "zone", zone)
				continue
			}

			zones[dns.Fqdn(zone)] = true
		}

		if len(zones) > 0 {
			a.zones = zones
		}
	}

	zlog.Info("Empty zones loaded", "zones", len(a.zones))

	return a
}

// (*AS112).Name name return middleware name.
func (a *AS112) Name() string { return name }

// (*AS112).ServeDNS serveDNS implements the Handle interface. A wire-born
// request never decodes here: non-arpa names pass on one case-folded
// suffix compare, arpa names that miss the empty zones — every legitimate
// reverse lookup — pass after a zero-allocation canonical suffix walk, and
// an empty-zone hit builds its response from parsed scalars.
func (a *AS112) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if ch.Request.Undecoded() {
		if !wireNameHasArpaSuffix(ch.Request.WireName()) {
			ch.Next(ctx)
			return
		}
		a.serveWire(ctx, ch)
		return
	}

	req := ch.Request.Msg()
	w := ch.Writer

	q := req.Question[0]

	// Case-insensitively, like every other name comparison here: the old
	// case-sensitive suffix check let 10.IN-ADDR.ARPA.-style spellings
	// leak past the empty zones to recursion.
	if n := len(q.Name); n < 5 || !strings.EqualFold(q.Name[n-5:], "arpa.") {
		ch.Next(ctx)
		return
	}

	zone := a.Match(q.Name, q.Qtype)

	if zone == rootzone {
		ch.Next(ctx)
		return
	}

	qname := strings.ToLower(q.Name)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative, msg.RecursionAvailable = true, true

	soaHeader := dns.RR_Header{
		Name:   q.Name,
		Rrtype: dns.TypeSOA,
		Class:  dns.ClassINET,
		Ttl:    86400,
	}
	soa := &dns.SOA{
		Hdr:     soaHeader,
		Ns:      zone,
		Mbox:    rootzone,
		Serial:  0,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  86400,
	}

	switch q.Qtype {
	case dns.TypeNS:
		if zone == qname {
			nsHeader := dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    0,
			}
			ns := &dns.NS{
				Hdr: nsHeader,
				Ns:  zone,
			}
			msg.Answer = append(msg.Answer, ns)
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	case dns.TypeSOA:
		if zone == qname {
			msg.Answer = append(msg.Answer, soa)
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	default:
		msg.Ns = append(msg.Ns, soa)
	}

	if zone != qname {
		msg.Rcode = dns.RcodeNameError
	}

	_ = w.WriteMsg(msg)

	ch.Cancel()
}

// serveWire answers or passes a wire-born arpa query without decoding it.
// The canonical form and its label offsets come from one stack-buffered
// walk, so the suffix probe against the zone set — Match's loop — indexes
// the map without building a string. The overwhelmingly common outcome, a
// reverse lookup under a delegated zone, continues down the chain
// undecoded; only an empty-zone hit builds strings, for the response it is
// about to write.
func (a *AS112) serveWire(ctx context.Context, ch *middleware.Chain) {
	req := ch.Request

	var buf [dnsname.MaxPresentationLength]byte
	var offs [dnsname.MaxLabels]int
	canon, n, ok := dnsname.AppendCanonicalLabels(buf[:0], req.WireName(), offs[:])
	if !ok {
		ch.Next(ctx)
		return
	}

	// Match strips the owner label for DS: the record lives at the parent.
	start := 0
	if req.Qtype() == dns.TypeDS {
		if n < 2 {
			ch.Next(ctx)
			return
		}
		start = 1
	}

	// An empty-zone hit finally pays for its string; misses index the map
	// straight off the stack buffer. wholeZone mirrors the decoded body's
	// zone == qname: the match began at the first unstripped label.
	zone := ""
	wholeZone := false
	for i := start; i < n; i++ {
		if suffix := canon[offs[i]:]; a.zones[string(suffix)] {
			zone = string(suffix)
			wholeZone = i == 0 && start == 0
			break
		}
	}
	if zone == "" {
		ch.Next(ctx)
		return
	}

	pres, ok := dnsname.AppendPresentation(buf[:0], req.WireName())
	if !ok {
		ch.Next(ctx)
		return
	}
	qname := string(pres)

	msg := new(dns.Msg)
	msg.MsgHdr = dns.MsgHdr{
		Id:                 req.ID(),
		Response:           true,
		Opcode:             req.Opcode(),
		Authoritative:      true,
		RecursionDesired:   req.RD(),
		RecursionAvailable: true,
		CheckingDisabled:   req.CD(),
	}
	msg.Question = []dns.Question{{Name: qname, Qtype: req.Qtype(), Qclass: req.Qclass()}}

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   qname,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		Ns:      zone,
		Mbox:    rootzone,
		Serial:  0,
		Refresh: 28800,
		Retry:   7200,
		Expire:  604800,
		Minttl:  86400,
	}

	switch req.Qtype() {
	case dns.TypeNS:
		if wholeZone {
			msg.Answer = append(msg.Answer, &dns.NS{
				Hdr: dns.RR_Header{
					Name:   qname,
					Rrtype: dns.TypeNS,
					Class:  dns.ClassINET,
					Ttl:    0,
				},
				Ns: zone,
			})
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	case dns.TypeSOA:
		if wholeZone {
			msg.Answer = append(msg.Answer, soa)
		} else {
			msg.Ns = append(msg.Ns, soa)
		}
	default:
		msg.Ns = append(msg.Ns, soa)
	}

	if !wholeZone {
		msg.Rcode = dns.RcodeNameError
	}

	_ = ch.Writer.WriteMsg(msg)
	ch.Cancel()
}

// (*AS112).Match match returns whether or not a name contains in the zones.
func (a *AS112) Match(name string, qtype uint16) string {
	name = dns.CanonicalName(name)

	if qtype == dns.TypeDS {
		off, end := dns.NextLabel(name, 0)

		name = name[off:]
		if end {
			return rootzone
		}
	}

	for off, end := 0, false; !end; off, end = dns.NextLabel(name, off) {
		if _, ok := a.zones[name[off:]]; ok {
			return name[off:]
		}
	}

	return rootzone
}

var defaultZones = map[string]bool{
	"10.in-addr.arpa.":              true,
	"16.172.in-addr.arpa.":          true,
	"17.172.in-addr.arpa.":          true,
	"18.172.in-addr.arpa.":          true,
	"19.172.in-addr.arpa.":          true,
	"20.172.in-addr.arpa.":          true,
	"21.172.in-addr.arpa.":          true,
	"22.172.in-addr.arpa.":          true,
	"23.172.in-addr.arpa.":          true,
	"24.172.in-addr.arpa.":          true,
	"25.172.in-addr.arpa.":          true,
	"26.172.in-addr.arpa.":          true,
	"27.172.in-addr.arpa.":          true,
	"28.172.in-addr.arpa.":          true,
	"29.172.in-addr.arpa.":          true,
	"30.172.in-addr.arpa.":          true,
	"31.172.in-addr.arpa.":          true,
	"168.192.in-addr.arpa.":         true,
	"64.100.in-addr.arpa.":          true,
	"65.100.in-addr.arpa.":          true,
	"66.100.in-addr.arpa.":          true,
	"67.100.in-addr.arpa.":          true,
	"68.100.in-addr.arpa.":          true,
	"69.100.in-addr.arpa.":          true,
	"70.100.in-addr.arpa.":          true,
	"71.100.in-addr.arpa.":          true,
	"72.100.in-addr.arpa.":          true,
	"73.100.in-addr.arpa.":          true,
	"74.100.in-addr.arpa.":          true,
	"75.100.in-addr.arpa.":          true,
	"76.100.in-addr.arpa.":          true,
	"77.100.in-addr.arpa.":          true,
	"78.100.in-addr.arpa.":          true,
	"79.100.in-addr.arpa.":          true,
	"80.100.in-addr.arpa.":          true,
	"81.100.in-addr.arpa.":          true,
	"82.100.in-addr.arpa.":          true,
	"83.100.in-addr.arpa.":          true,
	"84.100.in-addr.arpa.":          true,
	"85.100.in-addr.arpa.":          true,
	"86.100.in-addr.arpa.":          true,
	"87.100.in-addr.arpa.":          true,
	"88.100.in-addr.arpa.":          true,
	"89.100.in-addr.arpa.":          true,
	"90.100.in-addr.arpa.":          true,
	"91.100.in-addr.arpa.":          true,
	"92.100.in-addr.arpa.":          true,
	"93.100.in-addr.arpa.":          true,
	"94.100.in-addr.arpa.":          true,
	"95.100.in-addr.arpa.":          true,
	"96.100.in-addr.arpa.":          true,
	"97.100.in-addr.arpa.":          true,
	"98.100.in-addr.arpa.":          true,
	"99.100.in-addr.arpa.":          true,
	"100.100.in-addr.arpa.":         true,
	"101.100.in-addr.arpa.":         true,
	"102.100.in-addr.arpa.":         true,
	"103.100.in-addr.arpa.":         true,
	"104.100.in-addr.arpa.":         true,
	"105.100.in-addr.arpa.":         true,
	"106.100.in-addr.arpa.":         true,
	"107.100.in-addr.arpa.":         true,
	"108.100.in-addr.arpa.":         true,
	"109.100.in-addr.arpa.":         true,
	"110.100.in-addr.arpa.":         true,
	"111.100.in-addr.arpa.":         true,
	"112.100.in-addr.arpa.":         true,
	"113.100.in-addr.arpa.":         true,
	"114.100.in-addr.arpa.":         true,
	"115.100.in-addr.arpa.":         true,
	"116.100.in-addr.arpa.":         true,
	"117.100.in-addr.arpa.":         true,
	"118.100.in-addr.arpa.":         true,
	"119.100.in-addr.arpa.":         true,
	"120.100.in-addr.arpa.":         true,
	"121.100.in-addr.arpa.":         true,
	"122.100.in-addr.arpa.":         true,
	"123.100.in-addr.arpa.":         true,
	"124.100.in-addr.arpa.":         true,
	"125.100.in-addr.arpa.":         true,
	"126.100.in-addr.arpa.":         true,
	"127.100.in-addr.arpa.":         true,
	"0.in-addr.arpa.":               true,
	"127.in-addr.arpa.":             true,
	"254.169.in-addr.arpa.":         true,
	"2.0.192.in-addr.arpa.":         true,
	"100.51.198.in-addr.arpa.":      true,
	"113.0.203.in-addr.arpa.":       true,
	"255.255.255.255.in-addr.arpa.": true,
	"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.": true,
	"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.": true,
	"d.f.ip6.arpa.":             true,
	"8.e.f.ip6.arpa.":           true,
	"9.e.f.ip6.arpa.":           true,
	"a.e.f.ip6.arpa.":           true,
	"b.e.f.ip6.arpa.":           true,
	"8.b.d.0.1.0.0.2.ip6.arpa.": true,
	"empty.as112.arpa.":         true,
	"home.arpa.":                true,
}

const rootzone = "."

// arpaSuffixWire is "arpa." in wire form: one 4-byte label + root.
var arpaSuffixWire = []byte{4, 'a', 'r', 'p', 'a', 0}

// wireNameHasArpaSuffix reports whether the wire-form name ends in
// "arpa." under ASCII case folding.
func wireNameHasArpaSuffix(name []byte) bool {
	if len(name) < len(arpaSuffixWire) {
		return false
	}
	tail := name[len(name)-len(arpaSuffixWire):]
	for i, b := range arpaSuffixWire {
		got := tail[i]
		if got >= 'A' && got <= 'Z' {
			got += 'a' - 'A'
		}
		if got != b {
			return false
		}
	}
	return true
}

const name = "as112"
