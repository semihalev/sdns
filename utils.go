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
	r := rand.New(rand.NewSource(time.Now().Unix()))
	ret := make([]dns.RR, len(vals))
	perm := r.Perm(len(vals))
	for i, randIndex := range perm {
		ret[i] = vals[randIndex]
	}
	return ret
}
