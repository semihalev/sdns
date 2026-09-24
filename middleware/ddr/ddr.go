// Package ddr answers the special-use zone resolver.arpa (RFC 9462).
//
// A client that reached sdns over plain DNS asks _dns.resolver.arpa for SVCB
// records and learns the encrypted listeners from them: one record per
// transport, carrying the ALPN, the port and, for DoH, the URI template. The
// client then upgrades on its own, having checked that the listener's
// certificate lists the IP address it used for plain DNS.
//
// The zone is always answered here, never sent upstream: RFC 9462 §6.1 has a
// resolver keep resolver.arpa to itself, since an upstream's answer would
// designate the upstream's listeners, not this server's. With discovery off,
// or for any other name or type in the zone, the answer is NODATA.
package ddr

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

const (
	zone      = "resolver.arpa."
	discovery = "_dns.resolver.arpa."
	ttl       = 300

	// dohPath is the DoH URI template (RFC 9461 §5). The DoH listener
	// accepts any path, so the conventional one is advertised.
	dohPath = "/dns-query{?dns}"
)

// zoneWire is resolver.arpa. in wire form, the suffix every name in the zone
// ends with.
var zoneWire = []byte{8, 'r', 'e', 's', 'o', 'l', 'v', 'e', 'r', 4, 'a', 'r', 'p', 'a', 0}

// DDR answers resolver.arpa.
type DDR struct {
	// records are the SVCB answers for _dns.resolver.arpa, owner names
	// filled in per query; nil when discovery is off or has nothing to
	// advertise.
	records []*dns.SVCB
	soaNS   string
}

// New builds the discovery answer once, from the listeners and the name the
// configuration gives.
func New(cfg *config.Config) *DDR {
	d := &DDR{soaNS: zone}
	if !cfg.DDR.Enabled {
		return d
	}
	target, err := cfg.DDRTarget()
	if err != nil {
		// The config gate refuses this file; reached only by a caller that
		// skipped it. Answer NODATA rather than advertise a broken name.
		zlog.Warn("DDR disabled", "error", err.Error())
		return d
	}
	d.soaNS = target

	// Priority is preference: DoH first, the transport every client that
	// implements DDR speaks, then DoT, then DoQ.
	for _, l := range []struct {
		bind  string
		alpn  []string
		path  bool
		deflt uint16
	}{
		{cfg.BindDOH, []string{"h2", "h3"}, true, 443},
		{cfg.BindTLS, []string{"dot"}, false, 853},
		{cfg.BindDOQ, []string{"doq"}, false, 853},
	} {
		if l.bind == "" {
			continue
		}
		rr, ok := record(target, uint16(len(d.records)+1), l.bind, l.alpn, l.path, l.deflt) //nolint:gosec // G115 - at most three records
		if ok {
			d.records = append(d.records, rr)
		}
	}
	return d
}

// record builds one ServiceMode SVCB for a listener. The port is carried
// only when it differs from the transport's default (RFC 9461 §4.2), and a
// listener bound to a specific address offers it as a hint, which saves the
// client resolving the name before it can connect.
func record(target string, priority uint16, bind string, alpn []string, path bool, deflt uint16) (*dns.SVCB, bool) {
	host, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		return nil, false
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil || port == 0 {
		return nil, false
	}

	rr := &dns.SVCB{
		Hdr:      dns.RR_Header{Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: ttl},
		Priority: priority,
		Target:   target,
	}
	rr.Value = append(rr.Value, &dns.SVCBAlpn{Alpn: alpn})
	if uint16(port) != deflt {
		rr.Value = append(rr.Value, &dns.SVCBPort{Port: uint16(port)})
	}
	if addr, err := netip.ParseAddr(host); err == nil && !addr.IsUnspecified() {
		ip := net.IP(addr.Unmap().AsSlice())
		if addr.Unmap().Is4() {
			rr.Value = append(rr.Value, &dns.SVCBIPv4Hint{Hint: []net.IP{ip}})
		} else {
			rr.Value = append(rr.Value, &dns.SVCBIPv6Hint{Hint: []net.IP{ip}})
		}
	}
	if path {
		rr.Value = append(rr.Value, &dns.SVCBDoHPath{Template: dohPath})
	}
	return rr, true
}

// Name returns the middleware name.
func (d *DDR) Name() string { return name }

// ServeDNS answers names in resolver.arpa and passes everything else on. A
// wire-born request outside the zone passes on one suffix compare, without
// decoding.
func (d *DDR) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if ch.Request.Qclass() != dns.ClassINET {
		ch.Next(ctx)
		return
	}
	if ch.Request.Undecoded() {
		if !hasZoneSuffix(ch.Request.WireName()) {
			ch.Next(ctx)
			return
		}
	}

	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}
	if len(req.Question) == 0 || !dns.IsSubDomain(zone, strings.ToLower(req.Question[0].Name)) {
		ch.Next(ctx)
		return
	}

	_ = ch.Writer.WriteMsg(d.answer(req))
	ch.Cancel()
}

// answer is the SVCB set for the discovery question and NODATA for every
// other name or type in the zone (RFC 9462 §6.4).
func (d *DDR) answer(req *dns.Msg) *dns.Msg {
	q := req.Question[0]
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative, msg.RecursionAvailable = true, true

	if q.Qtype == dns.TypeSVCB && strings.EqualFold(q.Name, discovery) && len(d.records) > 0 {
		for _, rr := range d.records {
			c := dns.Copy(rr).(*dns.SVCB)
			c.Hdr.Name = q.Name
			msg.Answer = append(msg.Answer, c)
		}
		return msg
	}

	msg.Ns = []dns.RR{&dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
		Ns:      d.soaNS,
		Mbox:    ".",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  ttl,
	}}
	return msg
}

// hasZoneSuffix reports whether a wire-form name ends in resolver.arpa.
// under ASCII case folding. A match inside a label's data only costs a
// decode; the decoded check above is the one that decides.
func hasZoneSuffix(name []byte) bool {
	if len(name) < len(zoneWire) {
		return false
	}
	tail := name[len(name)-len(zoneWire):]
	for i, b := range zoneWire {
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

const name = "ddr"
