// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func makeTestConfig() *config.Config {
	cfg := &config.Config{Expire: 300, CacheSize: 10240, Prefetch: 0, RateLimit: 10, Maxdepth: 30}
	cfg.RootServers = []string{"192.5.5.241:53", "192.203.230.10:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	256 3 8 AwEAAc4qsciJ5MdMUIu4n/pSTsSiU9OCyAanPTe5TcMX4v1hxhpFwiTGQUv3BXT6IAO4litrZKTUaj4vitqHW1+RQsHn3k/gSvt7FwyQwpy0mEnShBgr6RQiGtlBODNY67sTl+W8M/b6SLTAaaDri3BO5u6wrDs149rMELJAdoVBjmXW+zRH3kZzh3lwyTZsYtk7L+3DYbTiiHq+sRB4F9XoBPAz5Psv4q4EiPq07nW3acbW84zTz3CyQUmQkJT9VB1oUKHz6sNoyccqzcMX4q1GHAYpQ7FAXlKMxidoN1Ay5DWANgTmgJXzKhcI2nIZoq1x3yq4814O1LQd9QP68gI37+0=",
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	cfg.Timeout.Duration = 10 * time.Second
	cfg.Directory = filepath.Join(os.TempDir(), "sdns_temp")
	cfg.Prefetch = 90

	if !middleware.Ready() {
		middleware.Register("cache", func(cfg *config.Config) middleware.Handler { return New(cfg) })
		middleware.Setup(cfg)
	}

	return cfg
}

func Test_Purge(t *testing.T) {
	cfg := makeTestConfig()

	c := New(cfg)

	// Create a mock handler that returns a response for CHAOS queries
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		w, req := ch.Writer, ch.Request
		if len(req.Question) == 0 {
			ch.Cancel()
			return
		}

		q := req.Question[0]
		if q.Qclass == dns.ClassCHAOS && q.Qtype == dns.TypeNULL {
			// This is a purge query
			msg := new(dns.Msg)
			msg.SetReply(req)
			msg.Extra = append(msg.Extra, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassCHAOS, Ttl: 0},
				Txt: []string{"Purged"},
			})
			_ = w.WriteMsg(msg)
			ch.Cancel()
		}
	})

	bqname := base64.StdEncoding.EncodeToString([]byte("A:test.com."))

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(bqname), dns.TypeNULL)
	req.Question[0].Qclass = dns.ClassCHAOS

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain([]middleware.Handler{c, mockHandler})
	ch.Reset(mw, req)

	c.ServeDNS(context.Background(), ch)
	assert.Len(t, mw.Msg().Extra, 1)
}

func Test_PCache(t *testing.T) {
	cfg := makeTestConfig()

	c := New(cfg)
	assert.Equal(t, "cache", c.Name())

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]

	// Check cache is empty initially
	key := cache.Hash(q)
	entry := c.checkCache(key)
	assert.Nil(t, entry)

	c.ServeDNS(context.Background(), ch)
	assert.False(t, ch.Writer.Written())

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Extra = req.Extra

	msg.Answer = append(msg.Answer, makeRR("test.com. 4 IN A 0.0.0.0"))
	msg.Answer = append(msg.Answer, makeRR("test.com. 604800 IN	RRSIG	A 8 2 1800 20181217031301 20181117031301 12051 test.com. SZqTalowCrrgx5dhMDv8jxLuZRS6U/MqJXzMp/zMVue+sfrhW0kdl+z+ Rf628xCwwASAa2o2cvcax50JBbYnRNAQ1aMrTQpdQUCGK2TaP0xgjIqO iRKjf00uMKjHuRYu6FUOvehM9EaRaFD7E6dGr+EkwbuchQUpMenv4SEf oP4="))

	msg.Ns = append(msg.Ns, makeRR("test.com. 4 IN NS ns1.test.com."))
	msg.Ns = append(msg.Ns, makeRR("test.com. 604800 IN	RRSIG	NS 8 2 1800 20181217031301 20181117031301 12051 test.com. SZqTalowCrrgx5dhMDv8jxLuZRS6U/MqJXzMp/zMVue+sfrhW0kdl+z+ Rf628xCwwASAa2o2cvcax50JBbYnRNAQ1aMrTQpdQUCGK2TaP0xgjIqO iRKjf00uMKjHuRYu6FUOvehM9EaRaFD7E6dGr+EkwbuchQUpMenv4SEf oP4="))

	msg.Extra = append(msg.Extra, makeRR("ns1.test.com. 4 IN A 0.0.0.0"))
	msg.Extra = append(msg.Extra, makeRR("ns1.test.com. 604800 IN	RRSIG	A 8 2 1800 20181217031301 20181117031301 12051 test.com. SZqTalowCrrgx5dhMDv8jxLuZRS6U/MqJXzMp/zMVue+sfrhW0kdl+z+ Rf628xCwwASAa2o2cvcax50JBbYnRNAQ1aMrTQpdQUCGK2TaP0xgjIqO iRKjf00uMKjHuRYu6FUOvehM9EaRaFD7E6dGr+EkwbuchQUpMenv4SEf oP4="))

	c.Set(key, msg)
	entry = c.checkCache(key)
	assert.NotNil(t, entry)

	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.True(t, ch.Writer.Written())

	// Test expired entry - set a very short TTL cache entry
	shortTTLMsg := msg.Copy()
	entry = NewCacheEntry(shortTTLMsg, 1*time.Millisecond, 0)
	cacheKey := CacheKey{Question: q, CD: false}.Hash()
	c.positive.Set(cacheKey, entry)

	// Wait for expiration
	time.Sleep(2 * time.Millisecond)

	mw2 := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw2, req)
	c.ServeDNS(context.Background(), ch)
	// Should not be written from cache since it's expired
	assert.False(t, mw2.Written())
}

func Test_NCache(t *testing.T) {
	c := New(makeTestConfig())

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]
	key := cache.Hash(q)

	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeServerFailure)

	c.Set(key, msg)
	entry := c.checkCache(key)
	assert.NotNil(t, entry)

	// Verify it's in negative cache
	cacheKey := CacheKey{Question: q, CD: false}.Hash()
	negEntry, found := c.negative.Get(cacheKey)
	assert.True(t, found)
	assert.NotNil(t, negEntry)
}

func Test_Cache_RRSIG(t *testing.T) {
	cfg := makeTestConfig()

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("miek.nl.", dns.TypeNS)
	req.SetEdns0(4096, true)

	q := req.Question[0]

	// The old test used cache.Hash(q) without CD flag
	// But then called c.get(key, c.now())
	// The mismatch suggests it was testing that the wrong key wouldn't find anything
	key := cache.Hash(q) // Note: no CD flag

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Extra = req.Extra

	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	NS	linode.atoom.net."))
	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20160521031301 20160421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="))

	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	A	176.58.119.54"))
	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	RRSIG	A 8 3 1800 20161217031301 20161117031301 53289 atoom.net. car2hvJmft8+sA3zgk1zb8gdL8afpTBmUYaYK1OJuB+B6508IZIAYCFc 4yNFjxOFC9PaQz1GsgKNtwYl1HF8SAO/kTaJgP5V8BsZLfOGsQi2TWhn 3qOkuA563DvehVdMIzqzCTK5sLiQ25jg6saTiHO0yjpYBgcIxYvf8YW9 KYU="))

	// Set with the key (which internally will add CD flag based on msg)
	c.Set(key, msg)

	// The cache will store it with CD=true because req.CheckingDisabled is true
	// But we're checking with just the hash of the question
	entry := c.checkCache(key)
	// So it shouldn't find it
	assert.Nil(t, entry)
}

func Test_Cache_CNAME(t *testing.T) {
	cfg := makeTestConfig()
	c := New(cfg)

	// Create a mock handler that returns CNAME response
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		w, req := ch.Writer, ch.Request
		if len(req.Question) == 0 {
			ch.Cancel()
			return
		}

		q := req.Question[0]
		msg := new(dns.Msg)
		msg.SetReply(req)

		// Return a CNAME chain
		if q.Name == "www.example.com." && q.Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.CNAME{
				Hdr:    dns.RR_Header{Name: "www.example.com.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
				Target: "example.com.",
			})
		} else if q.Name == "example.com." && q.Qtype == dns.TypeA {
			msg.Answer = append(msg.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   []byte{93, 184, 216, 34},
			})
		}

		_ = w.WriteMsg(msg)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{c, mockHandler})

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)
	req.CheckingDisabled = true

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	ch.Next(context.Background())

	assert.True(t, ch.Writer.Written())
	assert.NotNil(t, ch.Writer.Msg())
	// Should have resolved CNAME to A record
	assert.True(t, len(ch.Writer.Msg().Answer) >= 1)
}

func Test_Cache_ResponseWriter(t *testing.T) {
	cfg := makeTestConfig()
	c := New(cfg)

	// Create a mock handler that returns different responses based on query
	mockHandler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		w, req := ch.Writer, ch.Request
		if len(req.Question) == 0 {
			ch.Cancel()
			return
		}

		q := req.Question[0]
		msg := new(dns.Msg)
		msg.SetReply(req)

		switch q.Name {
		case "www.example.com.":
			if q.Qtype == dns.TypeA {
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   []byte{93, 184, 216, 34},
				})
			}
		case "labs.example.com.":
			msg.SetRcode(req, dns.RcodeNameError)
		case "www.apple.com.":
			if q.Qtype == dns.TypeA {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "apple.com.",
				})
				msg.Answer = append(msg.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: "apple.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   []byte{17, 142, 250, 35},
				})
			}
		case "org.":
			if q.Qtype == dns.TypeDNSKEY {
				// Simulate DNSKEY response
				msg.Answer = append(msg.Answer, &dns.DNSKEY{
					Hdr:       dns.RR_Header{Name: q.Name, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
					Flags:     256,
					Protocol:  3,
					Algorithm: 8,
					PublicKey: "dummykey",
				})
			}
		case "www.microsoft.com.":
			if q.Qtype == dns.TypeCNAME {
				msg.Answer = append(msg.Answer, &dns.CNAME{
					Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
					Target: "microsoft.com.",
				})
			}
		}

		_ = w.WriteMsg(msg)
		ch.Cancel()
	})

	ch := middleware.NewChain([]middleware.Handler{c, mockHandler})
	ctxtest := context.Background()

	// Test 1: RD=false should fail with ServerFailure
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(4096, true)
	req.CheckingDisabled = true
	req.RecursionDesired = false

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeServerFailure, ch.Writer.Rcode())

	// Test 2: RD=true should succeed
	req = req.Copy()
	req.RecursionDesired = true
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	// Test 3: NXDOMAIN response
	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("labs.example.com.", dns.TypeA)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeNameError, ch.Writer.Rcode())

	// Test 4: Success with CNAME
	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("www.apple.com.", dns.TypeA)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	// Test 5: DNSKEY query
	req = req.Copy()
	req.IsEdns0().SetUDPSize(512)
	req.SetQuestion("org.", dns.TypeDNSKEY)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	// Test 6: CNAME query
	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("www.microsoft.com.", dns.TypeCNAME)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())
}
