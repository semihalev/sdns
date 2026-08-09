package cache

import (
	"net/netip"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/stretchr/testify/assert"
)

func TestResolutionFailuresUseDedicatedCache(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("failure.example.", dns.TypeA)
	req.SetEdns0(1232, true)

	first := new(dns.Msg)
	first.SetReply(req)
	first.Rcode = dns.RcodeServerFailure
	dnsutil.SetEDE(first, dns.ExtendedErrorCodeNetworkError, "first failure")

	key := CacheKey{Question: req.Question[0], CD: false}.Hash()
	c.Set(key, first)

	if _, ok := c.negative.Get(key); ok {
		t.Fatal("SERVFAIL entered the legacy negative cache")
	}
	hit, ok := c.store.LookupFailure(req, netip.Prefix{})
	if !ok {
		t.Fatal("SERVFAIL missing from the RFC 9520 failure cache")
	}
	cached := hit.Response(req)
	ede := dnsutil.GetEDE(cached)
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeCachedError {
		t.Fatalf("cached failure EDE = %+v, want EDE 13", ede)
	}
	if cached.AuthenticatedData {
		t.Fatal("cached failure retained AD")
	}
}

func TestResolutionFailureRcodeClassification(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024})
	defer c.Stop()

	tests := []struct {
		name        string
		rcode       int
		wantFailure bool
	}{
		{"SUCCESS", dns.RcodeSuccess, false},
		{"SERVFAIL", dns.RcodeServerFailure, true},
		{"NXDOMAIN", dns.RcodeNameError, false},
		{"REFUSED", dns.RcodeRefused, true},
		{"FORMERR", dns.RcodeFormatError, true},
		{"NOTIMP", dns.RcodeNotImplemented, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := new(dns.Msg)
			msg.SetQuestion(tt.name+".test.", dns.TypeA)
			msg.SetRcode(msg, tt.rcode)
			if tt.rcode == dns.RcodeSuccess || tt.rcode == dns.RcodeNameError {
				msg.Ns = []dns.RR{&dns.SOA{
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
				}}
			}

			key := CacheKey{Question: msg.Question[0], CD: false}.Hash()
			c.Set(key, msg)

			_, inPositive := c.positive.Get(key)
			_, inLegacyNegative := c.negative.Get(key)
			req := new(dns.Msg)
			req.SetQuestion(msg.Question[0].Name, msg.Question[0].Qtype)
			_, inFailure := c.store.LookupFailure(req, netip.Prefix{})

			assert.False(t, inLegacyNegative, "legacy negative cache must remain empty")
			assert.Equal(t, tt.wantFailure, inFailure)
			assert.Equal(t, !tt.wantFailure, inPositive)
		})
	}
}
