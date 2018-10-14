package main

import (
	"errors"
	"fmt"

	"github.com/miekg/dns"
)

var (
	errNSECMismatch         = errors.New("NSEC3 record doesn't match question")
	errNSECTypeExists       = errors.New("NSEC3 record shows question type exists")
	errNSECMultipleCoverage = errors.New("Multiple NSEC3 records cover next closer/source of synthesis")
	errNSECMissingCoverage  = errors.New("NSEC3 record missing for expected encloser")
	errNSECBadDelegation    = errors.New("DS or SOA bit set in NSEC3 type map")
	errNSECNSMissing        = errors.New("NS bit not set in NSEC3 type map")
	errNSECOptOut           = errors.New("Opt-Out bit not set for NSEC3 record covering next closer")
)

func typesSet(set []uint16, types ...uint16) bool {
	tm := make(map[uint16]struct{}, len(types))
	for _, t := range types {
		tm[t] = struct{}{}
	}
	for _, t := range set {
		if _, present := tm[t]; present {
			return true
		}
	}
	return false
}

func findClosestEncloser(name string, nsec []dns.RR) (string, string) {
	labelIndices := dns.Split(name)
	nc := name
	for i := 0; i < len(labelIndices); i++ {
		z := name[labelIndices[i]:]
		_, err := findMatching(z, nsec)
		if err != nil {
			continue
		}
		if i != 0 {
			nc = name[labelIndices[i-1]:]
		}
		return z, nc
	}
	return "", ""
}

func findMatching(name string, nsec []dns.RR) ([]uint16, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if n.Match(name) {
			return n.TypeBitMap, nil
		}
	}
	return nil, errNSECMissingCoverage
}

func findCoverer(name string, nsec []dns.RR) ([]uint16, bool, error) {
	for _, rr := range nsec {
		n := rr.(*dns.NSEC3)
		if n.Cover(name) {
			return n.TypeBitMap, (n.Flags & 1) == 1, nil
		}
	}
	return nil, false, errNSECMissingCoverage
}

func verifyNameError(q *dns.Question, nsec []dns.RR) error {
	ce, _ := findClosestEncloser(q.Name, nsec)
	if ce == "" {
		return errNSECMissingCoverage
	}
	_, _, err := findCoverer(fmt.Sprintf("*.%s", ce), nsec)
	if err != nil {
		return err
	}
	return nil
}

func verifyNODATA(q *dns.Question, nsec []dns.RR) error {
	types, err := findMatching(q.Name, nsec)
	if err != nil {
		if q.Qtype != dns.TypeDS {
			return err
		}

		ce, nc := findClosestEncloser(q.Name, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, optOut, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return errNSECOptOut
		}
		return nil
	}

	if typesSet(types, q.Qtype, dns.TypeCNAME) {
		return errNSECTypeExists
	}

	return nil
}

func verifyDelegation(delegation string, nsec []dns.RR) error {
	types, err := findMatching(delegation, nsec)
	if err != nil {
		ce, nc := findClosestEncloser(delegation, nsec)
		if ce == "" {
			return errNSECMissingCoverage
		}
		_, optOut, err := findCoverer(nc, nsec)
		if err != nil {
			return err
		}
		if !optOut {
			return errNSECOptOut
		}
		return nil
	}
	if !typesSet(types, dns.TypeNS) {
		return errNSECNSMissing
	}
	if typesSet(types, dns.TypeDS, dns.TypeSOA) {
		return errNSECBadDelegation
	}
	return nil
}
