// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package dnsutil

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/response"
)

// See https://github.com/kubernetes/dns/issues/121, add some specific tests for those use cases.

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func TestMinimalTTL(t *testing.T) {
	utc := time.Now().UTC()

	mt, _ := response.Typify(nil, utc)
	if mt != response.OtherError {
		t.Fatalf("Expected type to be response.NoData, got %s", mt)
	}

	dur := MinimalTTL(nil, mt) // minTTL on msg is 3600 (neg. ttl on SOA)
	if dur != time.Duration(MinimalDefaultTTL) {
		t.Fatalf("Expected minttl duration to be %d, got %d", 1800, dur)
	}

	m := new(dns.Msg)
	m.SetQuestion("z.alm.im.", dns.TypeA)
	m.SetEdns0(dns.DefaultMsgSize, true)

	mt, _ = response.Typify(m, utc)
	if mt != response.NoError {
		t.Fatalf("Expected type to be response.NoData, got %s", mt)
	}
	dur = MinimalTTL(m, mt) // minTTL on msg is 3600 (neg. ttl on SOA)
	if dur != time.Duration(MinimalDefaultTTL) {
		t.Fatalf("Expected minttl duration to be %d, got %d", 1800, dur)
	}

	m.Ns = []dns.RR{
		makeRR("alm.im.	1800	IN	SOA	ivan.ns.cloudflare.com. dns.cloudflare.com. 2025042470 10000 2400 604800 3600"),
	}

	mt, _ = response.Typify(m, utc)
	if mt != response.NoData {
		t.Fatalf("Expected type to be response.NoData, got %s", mt)
	}

	dur = MinimalTTL(m, mt) // minTTL on msg is 3600 (neg. ttl on SOA)
	if dur != time.Duration(1800*time.Second) {
		t.Fatalf("Expected minttl duration to be %d, got %d", 1800, dur)
	}

	m.Extra = []dns.RR{
		makeRR("alm.im.	1200	IN	A	127.0.0.1"),
	}

	m.Rcode = dns.RcodeNameError
	mt, _ = response.Typify(m, utc)
	if mt != response.NameError {
		t.Fatalf("Expected type to be response.NameError, got %s", mt)
	}
	dur = MinimalTTL(m, mt) // minTTL on msg is 3600 (neg. ttl on SOA)
	if dur != time.Duration(1200*time.Second) {
		t.Fatalf("Expected minttl duration to be %d, got %d", 1800, dur)
	}

	m.Answer = []dns.RR{
		makeRR("z.alm.im.	600	IN	A	127.0.0.1"),
	}
	dur = MinimalTTL(m, mt) // minTTL on msg is 3600 (neg. ttl on SOA)
	if dur != time.Duration(600*time.Second) {
		t.Fatalf("Expected minttl duration to be %d, got %d", 1800, dur)
	}
}

func BenchmarkMinimalTTL(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion("example.org.", dns.TypeA)
	m.Ns = []dns.RR{
		makeRR("a.example.org. 	1800	IN	A 127.0.0.53"),
		makeRR("b.example.org. 	1900	IN	A 127.0.0.53"),
		makeRR("c.example.org. 	1600	IN	A 127.0.0.53"),
		makeRR("d.example.org. 	1100	IN	A 127.0.0.53"),
		makeRR("e.example.org. 	1000	IN	A 127.0.0.53"),
	}
	m.Extra = []dns.RR{
		makeRR("a.example.org. 	1800	IN	A 127.0.0.53"),
		makeRR("b.example.org. 	1600	IN	A 127.0.0.53"),
		makeRR("c.example.org. 	1400	IN	A 127.0.0.53"),
		makeRR("d.example.org. 	1200	IN	A 127.0.0.53"),
		makeRR("e.example.org. 	1100	IN	A 127.0.0.53"),
	}

	utc := time.Now().UTC()
	mt, _ := response.Typify(m, utc)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dur := MinimalTTL(m, mt)
		if dur != 1000*time.Second {
			b.Fatalf("Wrong MinimalTTL %d, expected %d", dur, 1000*time.Second)
		}
	}
}
