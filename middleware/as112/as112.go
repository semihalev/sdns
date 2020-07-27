package as112

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// AS112 type
type AS112 struct {
	zones map[string]bool
}

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return a new middleware
func New(cfg *config.Config) *AS112 {
	a := &AS112{zones: defaultZones}

	if len(cfg.EmptyZones) > 0 {
		zones := make(map[string]bool)

		for _, zone := range cfg.EmptyZones {
			if a.Match(zone, dns.TypeSOA) == rootzone {
				log.Error("Empty zone doesn't match in default empty zones, check your config!", "zone", zone)
				continue
			}

			zones[dns.Fqdn(zone)] = true
		}

		if len(zones) > 0 {
			a.zones = zones
		}
	}

	log.Info("Empty zones loaded", "zones", len(a.zones))

	return a
}

// Name return middleware name
func (a *AS112) Name() string { return name }

// ServeDNS implements the Handle interface.
func (a *AS112) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	w, req := ch.Writer, ch.Request

	q := req.Question[0]

	if !strings.HasSuffix(q.Name, "arpa.") {
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

// Match returns whether or not a name contains in the zones
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
const name = "as112"
