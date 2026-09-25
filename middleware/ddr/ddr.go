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
	"strings"
	"sync/atomic"

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
	// services are the configured encrypted listeners in preference order,
	// empty when discovery is off or has nothing to advertise.
	services []service
	target   string
	soaNS    string

	// v4hint and v6hint are the configured address hints, carried in every
	// record; nil carries none.
	v4hint, v6hint []net.IP

	// serving reports whether a listener of a transport is up. The server
	// sets it once the listeners are bound; until then, and for a DDR
	// driven without a server, every configured listener is advertised.
	serving atomic.Pointer[func(proto string) bool]
}

// service is one configured listener: the transports it answers on, each
// with the ALPN it speaks and the listener tag the server reports it under.
// DoH is one service on two listeners, HTTP/2 over TCP and HTTP/3 over
// QUIC, which bind and fail independently.
//
// A service carries no address of its own. The address a listener is bound
// to is not the one clients reach whenever anything stands in between, a
// load balancer, NAT, anycast, a reverse proxy, and the server cannot tell.
// Address hints come from the configuration alone; without them the client
// resolves the target name, which the operator controls.
type service struct {
	alpns []alpnListener
	port  uint16 // zero when it is the transport's default
	path  bool   // carries the DoH URI template
}

type alpnListener struct {
	alpn, proto string
}

// New takes the listeners and the name from the configuration. The records
// themselves are built per discovery query, from the listeners that are up
// at that moment.
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
	d.target, d.soaNS = target, target
	if d.v4hint, d.v6hint, err = cfg.DDRHints(); err != nil {
		// Refused by the config gate as well; a caller that skipped it
		// advertises no hint rather than a wrong one.
		zlog.Warn("DDR carries no address hints", "error", err.Error())
		d.v4hint, d.v6hint = nil, nil
	}

	// Preference order: DoH first, the transport every client that
	// implements DDR speaks, then DoT, then DoQ. The network is the one the
	// listener opens, which is how its port name is looked up.
	for _, l := range []struct {
		bind    string
		network string
		alpns   []alpnListener
		path    bool
		deflt   uint16
	}{
		{cfg.BindDOH, "tcp", []alpnListener{{"h2", "doh"}, {"h3", "doh3"}}, true, 443},
		{cfg.BindTLS, "tcp", []alpnListener{{"dot", "tls"}}, false, 853},
		{cfg.BindDOQ, "udp", []alpnListener{{"doq", "doq"}}, false, 853},
	} {
		if l.bind == "" {
			continue
		}
		svc, loopback, ok := newService(l.bind, l.network, l.alpns, l.path, l.deflt)
		if !ok {
			zlog.Warn("DDR skips a listener it cannot describe", "bind", l.bind)
			continue
		}
		if l.path {
			svc, loopback = published(cfg.DDR, svc, loopback)
		}
		if loopback {
			zlog.Warn("DDR skips a listener bound to loopback, which clients cannot reach; "+
				"a DoH listener behind a reverse proxy is advertised with ddr.doh_port", "bind", l.bind)
			continue
		}
		d.services = append(d.services, svc)
	}
	return d
}

// published describes DoH as a reverse proxy publishes it, when the
// configuration says so. A proxy port replaces the listener's port: clients
// connect to the proxy, found through the target name.
// Proxy ALPNs replace the listener's, and without them the listener's own
// stand for the proxy's. Either way, whichever HTTP version a client speaks
// to the proxy, the proxy reaches the listener over its TCP side, so each is
// offered while that side is up, never on the listener's own QUIC state.
func published(ddr config.DDRConfig, svc service, loopback bool) (service, bool) {
	if ddr.DoHPort == 0 && len(ddr.DoHALPN) == 0 {
		return svc, loopback
	}
	if ddr.DoHPort != 0 {
		svc.port, loopback = 0, false
		if ddr.DoHPort != 443 {
			svc.port = uint16(ddr.DoHPort) //nolint:gosec // G115 - range checked by the config gate
		}
	}
	alpns := ddr.DoHALPN
	if len(alpns) == 0 {
		for _, a := range svc.alpns {
			alpns = append(alpns, a.alpn)
		}
	}
	svc.alpns = make([]alpnListener, 0, len(alpns))
	for _, alpn := range alpns {
		svc.alpns = append(svc.alpns, alpnListener{alpn, "doh"})
	}
	return svc, loopback
}

// newService describes one listener. The port is resolved the way the
// listener and the config gate resolve it, service names included, and is
// carried only when it differs from the transport's default (RFC 9461 §4.2).
// loopback reports that the listener is bound to a loopback address, where
// no client can reach it.
func newService(bind, network string, alpns []alpnListener, path bool, deflt uint16) (svc service, loopback, ok bool) {
	host, portStr, err := net.SplitHostPort(bind)
	if err != nil {
		return service{}, false, false
	}
	port, err := net.LookupPort(network, portStr)
	if err != nil || port <= 0 || port > 65535 {
		return service{}, false, false
	}
	svc = service{alpns: alpns, path: path}
	if uint16(port) != deflt { //nolint:gosec // G115 - range checked above
		svc.port = uint16(port) //nolint:gosec // G115 - range checked above
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		loopback = addr.Unmap().IsLoopback()
	} else if name := strings.ToLower(strings.TrimSuffix(host, ".")); name == "localhost" || strings.HasSuffix(name, ".localhost") {
		// RFC 6761 §6.3: localhost and every name under it are loopback,
		// with or without the trailing dot.
		loopback = true
	}
	return svc, loopback, true
}

// ObserveListeners implements middleware.ListenerObserver.
func (d *DDR) ObserveListeners(serving func(proto string) bool) {
	d.serving.Store(&serving)
}

// records builds the discovery answer from the listeners that are up: a
// service with none of its transports up is left out, DoH offers only the
// HTTP versions it is serving, and priorities count the services offered.
func (d *DDR) records(owner string) []dns.RR {
	var up func(string) bool
	if p := d.serving.Load(); p != nil {
		up = *p
	}
	var out []dns.RR
	for _, svc := range d.services {
		var alpn []string
		for _, a := range svc.alpns {
			if up == nil || up(a.proto) {
				alpn = append(alpn, a.alpn)
			}
		}
		if len(alpn) == 0 {
			continue
		}
		rr := &dns.SVCB{
			Hdr:      dns.RR_Header{Name: owner, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: ttl},
			Priority: uint16(len(out) + 1), //nolint:gosec // G115 - at most three records
			Target:   d.target,
		}
		rr.Value = append(rr.Value, &dns.SVCBAlpn{Alpn: alpn})
		if svc.port != 0 {
			rr.Value = append(rr.Value, &dns.SVCBPort{Port: svc.port})
		}
		if len(d.v4hint) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv4Hint{Hint: d.v4hint})
		}
		if len(d.v6hint) > 0 {
			rr.Value = append(rr.Value, &dns.SVCBIPv6Hint{Hint: d.v6hint})
		}
		if svc.path {
			rr.Value = append(rr.Value, &dns.SVCBDoHPath{Template: dohPath})
		}
		out = append(out, rr)
	}
	return out
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

	if q.Qtype == dns.TypeSVCB && strings.EqualFold(q.Name, discovery) {
		if msg.Answer = d.records(q.Name); len(msg.Answer) > 0 {
			return msg
		}
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
