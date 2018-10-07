package main

import (
	"crypto/md5"
	"fmt"
	"math/rand"
	"strings"
	"time"

	"github.com/miekg/dns"
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
