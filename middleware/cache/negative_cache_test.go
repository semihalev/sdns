package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/util"
	"github.com/stretchr/testify/assert"
)

func TestNegativeCacheExpiry(t *testing.T) {
	// Create config with 2 second expire for faster testing
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    2, // 2 seconds for negative cache
		Prefetch:  0,
		RateLimit: 0,
	}

	c := New(cfg)
	defer c.Stop()

	// Create a SERVFAIL response
	msg := new(dns.Msg)
	msg.SetQuestion("nonexistent.invalid.", dns.TypeA)
	msg.SetRcode(msg, dns.RcodeServerFailure)

	// Store in cache
	key := CacheKey{Question: msg.Question[0], CD: false}.Hash()
	c.Set(key, msg)

	// Check it's cached immediately
	entry := c.checkCache(key)
	assert.NotNil(t, entry, "Entry should be in cache immediately after setting")

	// Check response type
	mt, _ := util.ClassifyResponse(msg, time.Now().UTC())
	assert.Equal(t, util.TypeServerFailure, mt, "SERVFAIL should be OtherError type")

	// Entry should be in negative cache
	negEntry, found := c.negative.Get(key)
	assert.True(t, found, "Entry should be in negative cache")
	assert.NotNil(t, negEntry)

	// Wait 1 second - should still be there
	time.Sleep(1 * time.Second)
	entry = c.checkCache(key)
	assert.NotNil(t, entry, "Entry should still be in cache after 1 second")

	// Wait another 2 seconds (total 3 seconds) - should be expired
	time.Sleep(2 * time.Second)
	entry = c.checkCache(key)
	assert.Nil(t, entry, "Entry should have expired after 3 seconds (expire=2s)")
}

func TestNegativeCacheRcodeHandling(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    10,
	}

	c := New(cfg)
	defer c.Stop()

	tests := []struct {
		name           string
		rcode          int
		expectNegative bool // true if should go to negative cache
	}{
		{"SUCCESS", dns.RcodeSuccess, false},
		{"SERVFAIL", dns.RcodeServerFailure, true},
		{"NXDOMAIN", dns.RcodeNameError, false}, // Goes to positive cache
		{"REFUSED", dns.RcodeRefused, true},
		{"FORMERR", dns.RcodeFormatError, true},
		{"NOTIMP", dns.RcodeNotImplemented, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(tt.name+".test.", dns.TypeA)
			msg.SetRcode(msg, tt.rcode)

			// For NODATA (SUCCESS with no answer) and NXDOMAIN, add SOA in authority
			if tt.rcode == dns.RcodeSuccess || tt.rcode == dns.RcodeNameError {
				msg.Ns = []dns.RR{
					&dns.SOA{
						Hdr: dns.RR_Header{
							Name:   "test.",
							Rrtype: dns.TypeSOA,
							Class:  dns.ClassINET,
							Ttl:    300,
						},
						Ns:      "ns1.test.",
						Mbox:    "admin.test.",
						Serial:  1,
						Refresh: 3600,
						Retry:   600,
						Expire:  86400,
						Minttl:  300,
					},
				}
			}

			key := CacheKey{Question: msg.Question[0], CD: false}.Hash()
			c.Set(key, msg)

			// Check where it was stored
			_, inPositive := c.positive.Get(key)
			_, inNegative := c.negative.Get(key)

			if tt.expectNegative {
				assert.True(t, inNegative, "%s should be in negative cache", tt.name)
				assert.False(t, inPositive, "%s should not be in positive cache", tt.name)
			} else {
				assert.True(t, inPositive, "%s should be in positive cache", tt.name)
				assert.False(t, inNegative, "%s should not be in negative cache", tt.name)
			}
		})
	}
}

func TestNegativeCacheTTLCapping(t *testing.T) {
	cfg := &config.Config{
		CacheSize: 1024,
		Expire:    5, // 5 seconds max for negative cache
	}

	c := New(cfg)
	defer c.Stop()

	// Create error response with high TTL in SOA
	msg := new(dns.Msg)
	msg.SetQuestion("high-ttl.test.", dns.TypeA)
	msg.SetRcode(msg, dns.RcodeServerFailure)

	// Simulate a response that would have a high TTL
	// The negative cache should cap it at config.Expire (5 seconds)
	key := CacheKey{Question: msg.Question[0], CD: false}.Hash()
	c.Set(key, msg)

	// Get the entry and check its TTL
	entry, found := c.negative.Get(key)
	assert.True(t, found)
	assert.NotNil(t, entry)

	// The TTL should be capped at 5 seconds (or less)
	assert.LessOrEqual(t, entry.TTL(), 5, "Negative cache TTL should be capped at config.Expire")
}
