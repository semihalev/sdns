package resolver

import (
	"encoding/base64"
	"errors"
	"math/rand"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

var (
	errNoDNSKEY               = errors.New("no DNSKEY records found")
	errMissingKSK             = errors.New("no KSK DNSKEY found for DS records")
	errFailedToConvertKSK     = errors.New("failed to convert KSK DNSKEY record to DS record")
	errMismatchingDS          = errors.New("KSK DNSKEY record does not match DS record from parent zone")
	errNoSignatures           = errors.New("no RRSIG records for zone that should be signed")
	errMissingDNSKEY          = errors.New("no matching DNSKEY found for RRSIG records")
	errInvalidSignaturePeriod = errors.New("incorrect signature validity period")
	errMissingSigned          = errors.New("signed records are missing")

	localIPaddrs []net.IP
)

func init() {
	rand.Seed(time.Now().UnixNano())

	var err error
	localIPaddrs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Find local ip addresses failed", "error", err.Error())
	}
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

func shuffleStr(vals []string) []string {
	perm := rand.Perm(len(vals))
	ret := make([]string, len(vals))

	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
	}

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
	out := []dns.RR{}
	tMap := make(map[uint16]struct{}, len(t))
	for _, t := range t {
		tMap[t] = struct{}{}
	}
	for _, r := range in {
		if _, ok := tMap[r.Header().Rrtype]; ok {
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
		//TODO: miek dns lib doesn't support GOST 34.11 currently
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

	sort.Strings(list)
	sort.Slice(list, func(i, j int) bool {
		return dns.CompareDomainName(qname, list[i]) < dns.CompareDomainName(qname, list[j])
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

// AcquireMsg returns an empty msg from pool
func AcquireMsg() *dns.Msg {
	v := reqPool.Get()
	if v == nil {
		return &dns.Msg{}
	}

	return v.(*dns.Msg)
}

// ReleaseMsg returns req to pool
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
	req.Question = nil
	req.Answer = nil
	req.Ns = nil
	req.Extra = nil

	reqPool.Put(req)
}

var connPool sync.Pool

// AcquireConn returns an empty conn from pool
func AcquireConn() *Conn {
	v := connPool.Get()
	if v == nil {
		return &Conn{}
	}
	return v.(*Conn)
}

// ReleaseConn returns req to pool
func ReleaseConn(co *Conn) {
	if co.Conn != nil {
		_ = co.Conn.Close()
	}

	co.UDPSize = 0
	co.Conn = nil

	connPool.Put(co)
}
