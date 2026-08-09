package cache

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func TestAnswerCacheUsesFullConfiguredCapacity(t *testing.T) {
	const (
		cacheSize = 1024
		entries   = 768
	)

	c := New(&config.Config{CacheSize: cacheSize, Expire: 300})
	defer c.Stop()

	for i := range entries {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("entry-%03d.capacity.example.", i), dns.TypeA)

		msg := new(dns.Msg)
		switch i % 3 {
		case 0:
			msg.SetReply(req)
			msg.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{
					Name:   req.Question[0].Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    60,
				},
				A: []byte{192, 0, 2, 1},
			}}
		case 1:
			msg.SetRcode(req, dns.RcodeNameError)
			msg.Ns = []dns.RR{capacityTestSOA()}
		default:
			msg.SetReply(req)
			msg.Ns = []dns.RR{capacityTestSOA()}
		}

		key := CacheKey{Question: req.Question[0]}.Hash()
		c.Set(key, msg)
	}

	if got := c.store.PositiveLen(); got != entries {
		t.Fatalf("positive cache retained %d entries, want %d within configured capacity %d", got, entries, cacheSize)
	}
	if got := c.store.NegativeLen(); got != 0 {
		t.Fatalf("legacy negative cache retained %d entries, want 0", got)
	}

	failReq := new(dns.Msg)
	failReq.SetQuestion("failure.capacity.example.", dns.TypeA)
	failure := new(dns.Msg)
	failure.SetRcode(failReq, dns.RcodeServerFailure)
	c.Set(CacheKey{Question: failReq.Question[0]}.Hash(), failure)

	if got := c.store.PositiveLen(); got != entries {
		t.Fatalf("SERVFAIL changed positive cache size to %d, want %d", got, entries)
	}
	if got := c.store.NegativeLen(); got != 0 {
		t.Fatalf("SERVFAIL entered legacy negative cache; size = %d", got)
	}
	if hit, ok := c.store.LookupFailure(failReq, netip.Prefix{}); !ok || hit.Kind != FailureKindQuestion {
		t.Fatalf("SERVFAIL missing from dedicated failure cache: hit=%#v ok=%v", hit, ok)
	}
}

func capacityTestSOA() *dns.SOA {
	return &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   "capacity.example.",
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      "ns1.capacity.example.",
		Mbox:    "hostmaster.capacity.example.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
}
