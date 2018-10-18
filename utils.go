package main

import (
	"crypto/md5"
	"errors"
	"fmt"
	"math/rand"
	"net"
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
	key := fmt.Sprintf("%x", x)
	return key
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
	for _, r := range parentDSSet {
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
