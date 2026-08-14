package resolver

import (
	"math/rand/v2"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/zlog/v2"
)

var (
	localIPaddrs []net.IP
)

func init() {
	var err error
	localIPaddrs, err = findLocalIPAddresses()
	if err != nil {
		zlog.Fatal("Find local ip addresses failed", zlog.String("error", err.Error()))
	}
}

func formatQuestion(q dns.Question) string {
	var sb strings.Builder
	sb.WriteString(strings.ToLower(q.Name))
	sb.WriteByte(' ')
	sb.WriteString(dns.ClassToString[q.Qclass])
	sb.WriteByte(' ')
	sb.WriteString(dns.TypeToString[q.Qtype])
	return sb.String()
}

func shuffleStr(vals []string) []string {
	ret := slices.Clone(vals)
	rand.Shuffle(len(ret), func(i, j int) {
		ret[i], ret[j] = ret[j], ret[i]
	})
	return ret
}

// searchAddrs collects usable NS addresses from an answer as heap-free
// netip values. Address strings are deliberately never materialized here:
// the whole downstream pipeline (glue caches, Server construction, dedup)
// is netip-native and derives its one canonical string per Server.
func searchAddrs(msg *dns.Msg) (addrs []netip.Addr, found bool) {
	found = false

	for _, rr := range msg.Answer {
		if r, ok := rr.(*dns.A); ok {
			addr, valid := usableAddr(r.A)
			if !valid || !addr.Is4() {
				continue
			}
			addrs = append(addrs, addr)
			found = true
		} else if r, ok := rr.(*dns.AAAA); ok {
			addr, valid := usableAddr(r.AAAA)
			if !valid {
				continue
			}
			addrs = append(addrs, addr)
			found = true
		}
	}

	return
}

func findLocalIPAddresses() ([]net.IP, error) {
	var list []net.IP
	tt, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, t := range tt {
		aa, err := t.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range aa {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}

			list = append(list, ipnet.IP)
		}
	}

	return list, nil
}

func isLocalIP(ip net.IP) (ok bool) {
	for _, l := range localIPaddrs {
		if ip.Equal(l) {
			ok = true
			return
		}
	}

	return
}

// usableAddr converts an RR address to its canonical netip value and applies
// the shared NS-address filters (local interface addresses, loopback). The
// bool is false when the address is malformed or filtered.
func usableAddr(ip net.IP) (netip.Addr, bool) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return netip.Addr{}, false
	}
	addr = addr.Unmap()
	if addr.IsLoopback() || isLocalIP(ip) {
		return netip.Addr{}, false
	}
	return addr, true
}

// appendUniqueAddr grows a small per-NS address list without duplicates.
func appendUniqueAddr(values []netip.Addr, value netip.Addr) []netip.Addr {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func isDO(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}

	return false
}

func sortHosts(hosts hostSet, qname string) []string {
	var list []string
	for name := range hosts {
		list = append(list, name)
	}

	slices.Sort(list)
	slices.SortFunc(list, func(a, b string) int {
		return dnsname.CompareSuffix(qname, b) - dnsname.CompareSuffix(qname, a)
	})

	return list
}

var reqPool sync.Pool

// AcquireMsg returns an empty msg from pool.
func AcquireMsg() *dns.Msg {
	v, _ := reqPool.Get().(*dns.Msg)
	if v == nil {
		return &dns.Msg{}
	}

	return v
}

// ReleaseMsg returns req to pool.
func ReleaseMsg(req *dns.Msg) {
	req.Id = 0
	req.Response = false
	req.Opcode = 0
	req.Authoritative = false
	req.Truncated = false
	req.RecursionDesired = false
	req.RecursionAvailable = false
	req.Zero = false
	req.AuthenticatedData = false
	req.CheckingDisabled = false
	req.Rcode = 0
	req.Compress = false
	clear(req.Question)
	clear(req.Answer)
	clear(req.Ns)
	clear(req.Extra)
	req.Question = nil
	req.Answer = nil
	req.Ns = nil
	req.Extra = nil

	reqPool.Put(req)
}

var connPool sync.Pool

// AcquireConn returns an empty conn from pool.
func AcquireConn() *Conn {
	v, _ := connPool.Get().(*Conn)
	if v == nil {
		return &Conn{}
	}
	return v
}

// ReleaseConn returns req to pool.
func ReleaseConn(co *Conn) {
	if co.Conn != nil {
		_ = co.Close()
	}

	co.UDPSize = 0
	co.Conn = nil

	connPool.Put(co)
}
