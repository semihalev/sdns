package as112

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/emptyzones"
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
			if !emptyzones.Covers(zone) {
				zlog.Error("Empty zone doesn't match in default empty zones, check your config!", "zone", zone)
				continue
			}

			// Canonical, not merely rooted: both lookup paths probe with
			// canonical lowercase names, so a mixed-case configured zone
			// stored verbatim would be a dead key that never serves.
			zones[dns.CanonicalName(zone)] = true
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
		if suffix := canon[offs[i]:]; hasKey(a.zones, suffix) {
			zone = string(suffix)
			wholeZone = i == 0 && start == 0
			break
		}
	}
	if zone == "" {
		ch.Next(ctx)
		return
	}

	// Unreachable refusal: the same bytes already passed the canonical
	// walk, and presentation rendering shares its acceptance.
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

// hasKey is Match's presence probe over a stack-buffered suffix: the map
// index conversion is allocation-free, and testing presence rather than
// the stored value keeps the two paths' semantics identical by
// construction.
func hasKey(zones map[string]bool, suffix []byte) bool {
	_, ok := zones[string(suffix)]
	return ok
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

var defaultZones = emptyzones.Default

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
