package resolver

import (
	"encoding/base64"
	"errors"
	"math/rand"
	"net"
	"strings"
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
	errBadAnswer              = errors.New("response contained a non-zero RCODE")
	errMissingSigned          = errors.New("signed records are missing")

	localIPs []string
)

func init() {
	rand.Seed(time.Now().UnixNano())

	var err error
	localIPs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Find local ip addresses failed", "error", err.Error())
	}
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

func randInt(min, max int) int {
	if min == max {
		return min
	}

	return rand.Intn(max-min) + min
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

	for _, ans := range msg.Answer {
		if arec, ok := ans.(*dns.A); ok {
			if isLocalIP(arec.A.String()) {
				continue
			}

			if net.ParseIP(arec.A.String()).IsLoopback() {
				continue
			}

			addrs = append(addrs, arec.A.String())
			found = true
		}
	}

	return
}

func findLocalIPAddresses() ([]string, error) {
	var list []string
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

			list = append(list, ipnet.IP.String())
		}
	}

	return list, nil
}

func isLocalIP(ip string) (ok bool) {
	for _, lip := range localIPs {
		if lip == ip {
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
		if _, present := tMap[r.Header().Rrtype]; present {
			if name != "" && !strings.EqualFold(name, r.Header().Name) {
				continue
			}
			out = append(out, r)
		}
	}
	return out
}

func verifyDS(keyMap map[uint16]*dns.DNSKEY, parentDSSet []dns.RR) error {
	for i, r := range parentDSSet {
		parentDS, ok := r.(*dns.DS)
		if !ok {
			continue
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
			return errFailedToConvertKSK
		}
		if ds.Digest != parentDS.Digest {
			if i != len(parentDSSet)-1 {
				continue
			}
			return errMismatchingDS
		}
		return nil
	}

	return errMissingKSK
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
	typesErrors := make(map[uint16]bool)

	for _, sigRR := range sigs {
		sig := sigRR.(*dns.RRSIG)
		types[sig.TypeCovered]++
		typesErrors[sig.TypeCovered] = false
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
			if !typesErrors[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
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
			if !typesErrors[sig.TypeCovered] && types[sig.TypeCovered] > 1 {
				typesErrors[sig.TypeCovered] = true
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
		typesErrors[sig.TypeCovered] = false
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
