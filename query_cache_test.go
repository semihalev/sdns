package main

import (
	"net"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func makeCache() QueryCache {
	return QueryCache{
		Backend:  make(map[string]*Mesg, Config.Maxcount),
		Maxcount: Config.Maxcount,
	}
}

func TestCache(t *testing.T) {
	const (
		testDomain = "www.google.com"
	)

	cache := makeCache()
	WallClock = clockwork.NewFakeClock()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)

	if err := cache.Set(testDomain, m); err != nil {
		t.Error(err)
	}

	if _, _, err := cache.Get(testDomain); err != nil {
		t.Error(err)
	}

	cache.Remove(testDomain)

	if _, _, err := cache.Get(testDomain); err == nil {
		t.Error("cache entry still existed after remove")
	}
}

func TestCacheTtl(t *testing.T) {
	const (
		testDomain = "www.google.com"
	)

	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock
	cache := makeCache()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)

	var attl uint32 = 10
	var aaaattl uint32 = 20
	nullroute := net.ParseIP(Config.Nullroute)
	nullroutev6 := net.ParseIP(Config.Nullroutev6)
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    attl,
		},
		A: nullroute}
	m.Answer = append(m.Answer, a)

	aaaa := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    aaaattl,
		},
		AAAA: nullroutev6}
	m.Answer = append(m.Answer, aaaa)

	if err := cache.Set(testDomain, m); err != nil {
		t.Error(err)
	}

	msg, _, err := cache.Get(testDomain)
	assert.Nil(t, err)

	for _, answer := range msg.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			assert.Equal(t, attl, answer.Header().Ttl, "TTL should be unchanged")
		case dns.TypeAAAA:
			assert.Equal(t, aaaattl, answer.Header().Ttl, "TTL should be unchanged")
		default:
			t.Error("Unexpected RR type")
		}
	}

	fakeClock.Advance(5 * time.Second)
	msg, _, err = cache.Get(testDomain)
	assert.Nil(t, err)

	for _, answer := range msg.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			assert.Equal(t, attl-5, answer.Header().Ttl, "TTL should be decreased")
		case dns.TypeAAAA:
			assert.Equal(t, aaaattl-5, answer.Header().Ttl, "TTL should be decreased")
		default:
			t.Error("Unexpected RR type")
		}
	}

	fakeClock.Advance(5 * time.Second)
	_, _, err = cache.Get(testDomain)
	assert.Nil(t, err)

	for _, answer := range msg.Answer {
		switch answer.Header().Rrtype {
		case dns.TypeA:
			assert.Equal(t, uint32(0), answer.Header().Ttl, "TTL should be zero")
		case dns.TypeAAAA:
			assert.Equal(t, aaaattl-10, answer.Header().Ttl, "TTL should be decreased")
		default:
			t.Error("Unexpected RR type")
		}
	}

	fakeClock.Advance(1 * time.Second)

	// accessing an expired key will return KeyExpired error
	_, _, err = cache.Get(testDomain)
	if _, ok := err.(KeyExpired); !ok {
		t.Error(err)
	}

	// accessing an expired key will remove it from the cache
	_, _, err = cache.Get(testDomain)

	if _, ok := err.(KeyNotFound); !ok {
		t.Error("cache entry still existed after expiring - ", err)
	}
}

func TestCacheTtlFrequentPolling(t *testing.T) {
	const (
		testDomain = "www.google.com"
	)

	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock
	cache := makeCache()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)

	var attl uint32 = 10
	nullroute := net.ParseIP(Config.Nullroute)
	a := &dns.A{
		Hdr: dns.RR_Header{
			Name:   testDomain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    attl,
		},
		A: nullroute}
	m.Answer = append(m.Answer, a)

	if err := cache.Set(testDomain, m); err != nil {
		t.Error(err)
	}

	msg, _, err := cache.Get(testDomain)
	assert.Nil(t, err)

	assert.Equal(t, attl, msg.Answer[0].Header().Ttl, "TTL should be unchanged")

	//Poll 50 times at 100ms intervals: the TTL should go down by 5s
	for i := 0; i < 50; i++ {
		fakeClock.Advance(100 * time.Millisecond)
		_, _, err := cache.Get(testDomain)
		assert.Nil(t, err)
	}

	msg, _, err = cache.Get(testDomain)
	assert.Nil(t, err)

	assert.Equal(t, attl-5, msg.Answer[0].Header().Ttl, "TTL should be decreased")

	cache.Remove(testDomain)

}
