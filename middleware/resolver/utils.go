package resolver

import (
	"encoding/base64"
	"math/rand/v2"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog"
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

func searchAddrs(msg *dns.Msg) (addrs []string, found bool) {
	found = false

	for _, rr := range msg.Answer {
		if r, ok := rr.(*dns.A); ok {
			if isLocalIP(r.A) {
				continue
			}

			if r.A.To4() == nil {
				continue
			}

			if r.A.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.A.String())
			found = true
		} else if r, ok := rr.(*dns.AAAA); ok {
			if isLocalIP(r.AAAA) {
				continue
			}

			if r.AAAA.To16() == nil {
				continue
			}

			if r.AAAA.IsLoopback() {
				continue
			}

			addrs = append(addrs, r.AAAA.String())
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

func extractRRSet(in []dns.RR, name string, t ...uint16) []dns.RR {
	if len(in) == 0 {
		return nil
	}

	// Pre-allocate with reasonable capacity
	out := make([]dns.RR, 0, min(len(in)/2, 10))

	// Optimize for common single-type queries
	if len(t) == 1 {
		targetType := t[0]
		for _, r := range in {
			if r.Header().Rrtype == targetType {
				if name != "" && !strings.EqualFold(name, r.Header().Name) {
					continue
				}
				out = append(out, r)
			}
		}
		return out
	}

	// For multiple types, use map
	template := make(map[uint16]struct{}, len(t))
	for _, typ := range t {
		template[typ] = struct{}{}
	}
	for _, r := range in {
		if _, ok := template[r.Header().Rrtype]; ok {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

func verifyDS(keyMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) (bool, error) {
	unsupportedDigest := false
	for i, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
		}

		if parentDS.DigestType == dns.GOST94 {
			unsupportedDigest = true
		}

		ksk, present := keyMap[parentDS.KeyTag]
		if !present {
			continue
		}
		// GOST R 34.11-94 (digest type 3) not supported by miekg/dns library
		// RFC 8624: MUST NOT use for new DS records, deprecated since 2012
		// Usage: <119 keys worldwide (~0.01% of DNSSEC deployments)
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			if i != len(parentDSSet)-1 {
				continue
			}
			return unsupportedDigest, errMismatchingDS
		}
		return unsupportedDigest, nil
	}

	return unsupportedDigest, errMissingKSK
}

func isDO(req *dns.Msg) bool {
	if opt := req.IsEdns0(); opt != nil {
		return opt.Do()
	}

	return false
}

func verifyRRSIG(keys map[uint16]*dns.DNSKEY, msg *dns.Msg) (bool, error) {
	rr := msg.Answer
	if len(rr) == 0 {
		rr = msg.Ns
	}

	sigs := extractRRSet(rr, "", dns.TypeRRSIG)
	if len(sigs) == 0 {
		return false, errNoSignatures
	}

	types := make(map[uint16]int)
	typesErrors := make(map[uint16][]struct{})

	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		types[sig.TypeCovered]++
	}

main:
	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		for _, k := range keys {
			if !strings.HasSuffix(sig.Header().Name, k.Header().Name) {
				continue main
			}
			if sig.SignerName != k.Header().Name {
				continue main
			}
		}

		rest := extractRRSet(rr, strings.ToLower(sig.Header().Name), sig.TypeCovered)
		if len(rest) == 0 {
			return false, errMissingSigned
		}
		k, ok := keys[sig.KeyTag]
		if !ok {
			if len(typesErrors[sig.TypeCovered]) < types[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
				continue
			}
			return false, errMissingDNSKEY
		}
		switch k.Algorithm {
		case dns.RSASHA1, dns.RSASHA1NSEC3SHA1, dns.RSASHA256, dns.RSASHA512, dns.RSAMD5:
			if !checkExponent(k.PublicKey) {
				if len(typesErrors[sig.TypeCovered]) < types[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
					typesErrors[sig.TypeCovered] = append(typesErrors[sig.TypeCovered], struct{}{})
					continue
				}
				return false, nil
			}
		}
		err := sig.Verify(k, rest)
		if err != nil {
			if len(typesErrors[sig.TypeCovered]) < types[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
				typesErrors[sig.TypeCovered] = append(typesErrors[sig.TypeCovered], struct{}{})
				continue
			}
			return false, err
		}
		if !sig.ValidityPeriod(time.Time{}) {
			if types[sig.TypeCovered] > 1 {
				continue
			}
			return false, errInvalidSignaturePeriod
		}
	}

	return true, nil
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
	return
}

func verifyNSEC(q dns.Question, nsecSet []dns.RR) (typeMatch bool) {
	for _, rr := range nsecSet {
		nsec := rr.(*dns.NSEC)
		for _, t := range nsec.TypeBitMap {
			if t == q.Qtype {
				typeMatch = true
				break
			}
		}
	}

	return
}

func checkExponent(key string) bool {
	keybuf, err := fromBase64([]byte(key))
	if err != nil {
		return true
	}

	if len(keybuf) < 1+1+64 {
		// Exponent must be at least 1 byte and modulus at least 64
		return true
	}

	// RFC 2537/3110, section 2. RSA Public KEY Resource Records
	// Length is in the 0th byte, unless its zero, then it
	// it in bytes 1 and 2 and its a 16 bit number
	explen := uint16(keybuf[0])
	keyoff := 1
	if explen == 0 {
		explen = uint16(keybuf[1])<<8 | uint16(keybuf[2])
		keyoff = 3
	}

	if explen > 4 || explen == 0 || keybuf[keyoff] == 0 {
		// Exponent larger than supported by the crypto package,
		// empty, or contains prohibited leading zero.
		return false
	}

	return true
}

func sortnss(nss nameservers, qname string) []string {
	var list []string
	for name := range nss {
		list = append(list, name)
	}

	slices.Sort(list)
	slices.SortFunc(list, func(a, b string) int {
		return dns.CompareDomainName(qname, b) - dns.CompareDomainName(qname, a)
	})

	return list
}

func getDnameTarget(msg *dns.Msg) string {
	var target string

	q := msg.Question[0]

	for _, r := range msg.Answer {
		if dname, ok := r.(*dns.DNAME); ok {
			if n := dns.CompareDomainName(dname.Header().Name, q.Name); n > 0 {
				labels := dns.CountLabel(q.Name)

				if n == labels {
					target = dname.Target
				} else {
					prev, _ := dns.PrevLabel(q.Name, n)
					target = q.Name[:prev] + dname.Target
				}
			}

			return target
		}
	}

	return target
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
		_ = co.Conn.Close()
	}

	co.UDPSize = 0
	co.Conn = nil

	connPool.Put(co)
}
