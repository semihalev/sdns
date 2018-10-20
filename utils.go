package main

import (
	"bytes"
	"crypto/md5"
	"encoding/base64"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
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
)

func keyGen(q Question) string {
	h := md5.New()
	h.Write([]byte(q.String()))
	x := h.Sum(nil)

	return hex.EncodeToString(x)
}

func unFqdn(s string) string {
	s = strings.ToLower(s)
	if dns.IsFqdn(s) {
		return s[:len(s)-1]
	}
	return s
}

func upperName(s string) string {

	idx := strings.Index(s, ".")
	if idx != -1 {
		return s[idx+1:]
	}

	return s
}

func shuffleRR(vals []dns.RR) []dns.RR {

	r := newRand()
	perm := r.Perm(len(vals))
	ret := make([]dns.RR, len(vals))

	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
	}

	return ret
}

func shuffleStr(vals []string) []string {

	r := newRand()
	perm := r.Perm(len(vals))
	ret := make([]string, len(vals))

	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
	}

	return ret
}

func newRand() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().Unix()))
}

func searchAddr(msg *dns.Msg) (addr string, found bool) {

	found = false
	for _, ans := range msg.Answer {

		if arec, ok := ans.(*dns.A); ok {
			addr = arec.A.String()
			found = true
			break
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

			v4 := ipnet.IP.To4()
			if v4 == nil {
				continue
			}

			list = append(list, v4.String())
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
			if name != "" && name != strings.ToLower(r.Header().Name) {
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
		ds := ksk.ToDS(parentDS.DigestType)
		if ds == nil {
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

func clearOPT(msg *dns.Msg) *dns.Msg {
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

func clearDNSSEC(msg *dns.Msg) *dns.Msg {
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

func verifyRRSIG(keys map[uint16]*dns.DNSKEY, msg *dns.Msg) error {
	rr := msg.Answer
	if len(rr) == 0 {
		rr = msg.Ns
	}

	sigs := extractRRSet(rr, "", dns.TypeRRSIG)
	if len(sigs) == 0 {
		return errNoSignatures
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
		rest := extractRRSet(rr, sig.Header().Name, sig.TypeCovered)
		if len(rest) == 0 {
			return errMissingSigned
		}
		k, present := keys[sig.KeyTag]
		if !present {
			return errMissingDNSKEY
		}
		err := sig.Verify(k, rest)
		if err != nil {
			return err
		}
		if !sig.ValidityPeriod(time.Time{}) {
			return errInvalidSignaturePeriod
		}
	}

	return nil
}

func fromBase64(s []byte) (buf []byte, err error) {
	buflen := base64.StdEncoding.DecodedLen(len(s))
	buf = make([]byte, buflen)
	n, err := base64.StdEncoding.Decode(buf, s)
	buf = buf[:n]
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

func ameleCompare(a, b []*AuthServer) bool {

	if len(a) != len(b) {
		return false
	}

	sort.Slice(a, func(i, j int) bool {
		return a[i].Host > a[j].Host
	})

	sort.Slice(b, func(i, j int) bool {
		return b[i].Host > b[j].Host
	})

	for i := 0; i < len(a); i++ {
		if a[i].Host != b[i].Host || int64(a[i].RTT) != int64(b[i].RTT) {
			return false
		}
	}

	return true
}

func hashCompare(a, b []*AuthServer) bool {
	buf1 := []byte{}
	buf2 := []byte{}

	aj, _ := json.Marshal(a)
	bj, _ := json.Marshal(b)

	buf1 = append(buf1, aj...)
	buf2 = append(buf2, bj...)

	//TODO: sha256.New()
	return md5.Sum(buf1) == md5.Sum(buf2)
}

func byteCompare(a, b []*AuthServer) bool {
	var ab, bb bytes.Buffer
	aenc := gob.NewEncoder(&ab)
	benc := gob.NewEncoder(&bb)

	_ = aenc.Encode(a)
	_ = benc.Encode(b)

	return bytes.Compare(ab.Bytes(), bb.Bytes()) == 0
}
