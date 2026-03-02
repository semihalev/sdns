package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func TestCacheForEachEntryIteratesPositiveAndNegative(t *testing.T) {
	c := New(&config.Config{
		CacheSize: 2048,
		Expire:    60,
	})

	posMsg := new(dns.Msg)
	posMsg.SetQuestion("positive.example.", dns.TypeA)
	posMsg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "positive.example.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
		},
	}
	posKey := CacheKey{Question: posMsg.Question[0], CD: false}.Hash()
	c.positive.Set(posKey, NewCacheEntryWithKey(posMsg, 60*time.Second, 0, posKey))

	negMsg := new(dns.Msg)
	negMsg.SetQuestion("negative.example.", dns.TypeA)
	negMsg.Rcode = dns.RcodeServerFailure
	negKey := CacheKey{Question: negMsg.Question[0], CD: false}.Hash()
	c.negative.Set(negKey, NewCacheEntryWithKey(negMsg, 60*time.Second, 0, negKey))

	seenPos := false
	seenNeg := false

	c.ForEachEntry(func(positive bool, key uint64, entry *CacheEntry) bool {
		if entry == nil {
			t.Fatal("entry must not be nil")
		}

		switch key {
		case posKey:
			if !positive {
				t.Fatal("positive entry reported as negative")
			}
			seenPos = true
		case negKey:
			if positive {
				t.Fatal("negative entry reported as positive")
			}
			seenNeg = true
		}

		return true
	})

	if !seenPos {
		t.Fatal("expected positive entry to be iterated")
	}
	if !seenNeg {
		t.Fatal("expected negative entry to be iterated")
	}
}

func TestCacheForEachEntryStopsWhenCallbackReturnsFalse(t *testing.T) {
	c := New(&config.Config{
		CacheSize: 2048,
		Expire:    60,
	})

	msg := new(dns.Msg)
	msg.SetQuestion("stop.example.", dns.TypeA)
	msg.Answer = []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "stop.example.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    60,
			},
		},
	}
	key := CacheKey{Question: msg.Question[0], CD: false}.Hash()
	c.positive.Set(key, NewCacheEntryWithKey(msg, 60*time.Second, 0, key))

	negMsg := new(dns.Msg)
	negMsg.SetQuestion("should-not-visit.example.", dns.TypeA)
	negMsg.Rcode = dns.RcodeServerFailure
	negKey := CacheKey{Question: negMsg.Question[0], CD: false}.Hash()
	c.negative.Set(negKey, NewCacheEntryWithKey(negMsg, 60*time.Second, 0, negKey))

	calls := 0
	c.ForEachEntry(func(_ bool, _ uint64, _ *CacheEntry) bool {
		calls++
		return false
	})

	if calls != 1 {
		t.Fatalf("expected exactly one callback invocation, got %d", calls)
	}
}
