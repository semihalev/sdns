package dnsutil

import (
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/mock"
)

// ExtractAddressFromReverse turns a standard PTR reverse record name
// into an IP address. This works for ipv4 or ipv6.
//
// 54.119.58.176.in-addr.arpa. becomes 176.58.119.54. If the conversion
// fails the empty string is returned.
func ExtractAddressFromReverse(reverseName string) string {
	search := ""

	f := reverse

	switch {
	case strings.HasSuffix(reverseName, IP4arpa):
		search = strings.TrimSuffix(reverseName, IP4arpa)
	case strings.HasSuffix(reverseName, IP6arpa):
		search = strings.TrimSuffix(reverseName, IP6arpa)
		f = reverse6
	default:
		return ""
	}

	// Reverse the segments and then combine them.
	return f(strings.Split(search, "."))
}

// IsReverse returns 0 is name is not in a reverse zone. Anything > 0 indicates
// name is in a reverse zone. The returned integer will be 1 for in-addr.arpa. (IPv4)
// and 2 for ip6.arpa. (IPv6).
func IsReverse(name string) int {
	if strings.HasSuffix(name, IP4arpa) {
		return 1
	}
	if strings.HasSuffix(name, IP6arpa) {
		return 2
	}
	return 0
}

func reverse(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	ip := net.ParseIP(strings.Join(slice, ".")).To4()
	if ip == nil {
		return ""
	}
	return ip.String()
}

// reverse6 reverse the segments and combine them according to RFC3596:
// b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2
// is reversed to 2001:db8::567:89ab
func reverse6(slice []string) string {
	for i := 0; i < len(slice)/2; i++ {
		j := len(slice) - i - 1
		slice[i], slice[j] = slice[j], slice[i]
	}
	slice6 := []string{}
	for i := 0; i < len(slice)/4; i++ {
		slice6 = append(slice6, strings.Join(slice[i*4:i*4+4], ""))
	}
	ip := net.ParseIP(strings.Join(slice6, ":")).To16()
	if ip == nil {
		return ""
	}
	return ip.String()
}

// HandleFailed returns message specified with rcode.
func HandleFailed(req *dns.Msg, rcode int, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.Extra = req.Extra
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(do)
	}

	return m
}

// SetEdns0 returns replaced or new opt rr and if request has do
func SetEdns0(req *dns.Msg) (*dns.OPT, bool) {
	do := false
	opt := req.IsEdns0()

	if opt != nil {
		opt.SetUDPSize(DefaultMsgSize)
		if opt.Version() != 0 {
			return opt, false
		}

		ops := opt.Option

		opt.Option = []dns.EDNS0{}

		for _, option := range ops {
			if option.Option() == dns.EDNS0SUBNET {
				opt.Option = append(opt.Option, option)
			}
		}

		do = opt.Do()

		opt.Header().Ttl = 0
		opt.SetDo()
	} else {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(DefaultMsgSize)
		opt.SetDo()

		req.Extra = append(req.Extra, opt)
	}

	return opt, do
}

// ClearOPT returns cleared opt message
func ClearOPT(msg *dns.Msg) *dns.Msg {
	extra := make([]dns.RR, len(msg.Extra))
	copy(extra, msg.Extra)

	msg.Extra = []dns.RR{}

	for _, rr := range extra {
		switch rr.(type) {
		case *dns.OPT:
			continue
		default:
			msg.Extra = append(msg.Extra, rr)
		}
	}

	return msg
}

// ClearDNSSEC returns cleared RRSIG and NSECx message
func ClearDNSSEC(msg *dns.Msg) *dns.Msg {
	answer := make([]dns.RR, len(msg.Answer))
	copy(answer, msg.Answer)

	msg.Answer = []dns.RR{}

	for _, rr := range answer {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC3, *dns.NSEC:
			continue
		default:
			msg.Answer = append(msg.Answer, rr)
		}
	}

	ns := make([]dns.RR, len(msg.Ns))
	copy(ns, msg.Ns)

	msg.Ns = []dns.RR{}

	for _, rr := range ns {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC3, *dns.NSEC:
			continue
		default:
			msg.Ns = append(msg.Ns, rr)
		}
	}

	return msg
}

// ExchangeInternal exchange request internal
func ExchangeInternal(Net string, req *dns.Msg) (*dns.Msg, error) {
	mw := mock.NewWriter(Net, "127.0.0.1")
	dns.DefaultServeMux.ServeDNS(mw, req)

	if !mw.Written() {
		return nil, dns.ErrShortRead
	}

	return mw.Msg(), nil
}

const (
	// IP4arpa is the reverse tree suffix for v4 IP addresses.
	IP4arpa = ".in-addr.arpa."
	// IP6arpa is the reverse tree suffix for v6 IP addresses.
	IP6arpa = ".ip6.arpa."
	// DefaultMsgSize EDNS0 message size
	DefaultMsgSize = 1536
)
