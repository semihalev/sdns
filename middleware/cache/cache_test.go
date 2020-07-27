// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func Test_PCache(t *testing.T) {
	cfg := &config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1}
	cfg.RootServers = []string{"192.5.5.241:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	256 3 8 AwEAAc4qsciJ5MdMUIu4n/pSTsSiU9OCyAanPTe5TcMX4v1hxhpFwiTGQUv3BXT6IAO4litrZKTUaj4vitqHW1+RQsHn3k/gSvt7FwyQwpy0mEnShBgr6RQiGtlBODNY67sTl+W8M/b6SLTAaaDri3BO5u6wrDs149rMELJAdoVBjmXW+zRH3kZzh3lwyTZsYtk7L+3DYbTiiHq+sRB4F9XoBPAz5Psv4q4EiPq07nW3acbW84zTz3CyQUmQkJT9VB1oUKHz6sNoyccqzcMX4q1GHAYpQ7FAXlKMxidoN1Ay5DWANgTmgJXzKhcI2nIZoq1x3yq4814O1LQd9QP68gI37+0=",
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}

	c := New(cfg)
	assert.Equal(t, "cache", c.Name())

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]

	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	key := cache.Hash(q)
	_, found := c.get(key, now)
	assert.False(t, found)

	_, _, err := c.GetP(key, req)
	assert.Error(t, err)

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
	i, found := c.get(key, now)
	assert.True(t, found)
	assert.NotNil(t, i)

	_, _, err = c.GetP(key, req)
	assert.NoError(t, err)

	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.True(t, ch.Writer.Written())

	i.stored = time.Now().Add(-5 * time.Second)

	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.False(t, ch.Writer.Written())
}

func Test_NCache(t *testing.T) {
	c := New(&config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1})

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)

	q := req.Question[0]

	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	key := cache.Hash(q)

	_, err := c.GetN(key, req)
	assert.Error(t, err)

	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeServerFailure)

	c.Set(key, msg)
	i, found := c.get(key, now)
	assert.True(t, found)
	assert.NotNil(t, i)

	_, err = c.GetN(key, req)
	assert.NoError(t, err)
}

func Test_Cache_RRSIG(t *testing.T) {
	cfg := &config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1}
	cfg.Timeout.Duration = 10 * time.Second

	c := New(cfg)

	req := new(dns.Msg)
	req.SetQuestion("miek.nl.", dns.TypeNS)
	req.SetEdns0(4096, true)

	q := req.Question[0]
	key := cache.Hash(q)

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Extra = req.Extra

	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	NS	linode.atoom.net."))
	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20160521031301 20160421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="))

	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	A	176.58.119.54"))
	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	RRSIG	A 8 3 1800 20161217031301 20161117031301 53289 atoom.net. car2hvJmft8+sA3zgk1zb8gdL8afpTBmUYaYK1OJuB+B6508IZIAYCFc 4yNFjxOFC9PaQz1GsgKNtwYl1HF8SAO/kTaJgP5V8BsZLfOGsQi2TWhn 3qOkuA563DvehVdMIzqzCTK5sLiQ25jg6saTiHO0yjpYBgcIxYvf8YW9 KYU="))

	c.Set(key, msg)

	_, found := c.get(key, c.now())
	assert.False(t, found)
}

func Test_Cache_CNAME(t *testing.T) {
	cfg := &config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1}
	cfg.Timeout.Duration = 10 * time.Second

	c := New(cfg)

	m1 := new(dns.Msg)
	m1.SetQuestion("www.example.com.", dns.TypeA)
	m1.SetEdns0(4096, true)
	m1.Answer = append(m1.Answer, makeRR("www.example.com.		1800	IN	CNAME	www.example.com.example.net."))
	c.Set(cache.Hash(m1.Question[0]), m1)

	m2 := new(dns.Msg)
	m2.SetQuestion("www.example.com.example.net.", dns.TypeA)
	m2.SetEdns0(4096, true)
	m2.Answer = append(m2.Answer, makeRR("www.example.com.example.net.		1800	IN	CNAME	e6858.dsce9.example.net."))
	c.Set(cache.Hash(m2.Question[0]), m2)

	m3 := new(dns.Msg)
	m3.SetQuestion("e6858.dsce9.example.net.", dns.TypeA)
	m3.SetEdns0(4096, true)
	m3.Answer = append(m3.Answer, makeRR("e6858.dsce9.example.net. 10	IN	A	0.0.0.0"))
	c.Set(cache.Hash(m3.Question[0]), m3)

	ch := middleware.NewChain([]middleware.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.True(t, ch.Writer.Written())
	assert.Equal(t, 3, len(ch.Writer.Msg().Answer))

	c.now = func() time.Time {
		return time.Now().Add(time.Hour)
	}

	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	c.ServeDNS(context.Background(), ch)
	assert.False(t, ch.Writer.Written())
}

func Test_Cache_ResponseWriter(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(3, log.StdoutHandler))

	cfg := &config.Config{Expire: 300, CacheSize: 10240, RateLimit: 10, Maxdepth: 30}
	cfg.RootServers = []string{"192.5.5.241:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	256 3 8 AwEAAc4qsciJ5MdMUIu4n/pSTsSiU9OCyAanPTe5TcMX4v1hxhpFwiTGQUv3BXT6IAO4litrZKTUaj4vitqHW1+RQsHn3k/gSvt7FwyQwpy0mEnShBgr6RQiGtlBODNY67sTl+W8M/b6SLTAaaDri3BO5u6wrDs149rMELJAdoVBjmXW+zRH3kZzh3lwyTZsYtk7L+3DYbTiiHq+sRB4F9XoBPAz5Psv4q4EiPq07nW3acbW84zTz3CyQUmQkJT9VB1oUKHz6sNoyccqzcMX4q1GHAYpQ7FAXlKMxidoN1Ay5DWANgTmgJXzKhcI2nIZoq1x3yq4814O1LQd9QP68gI37+0=",
		".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	}
	cfg.Timeout.Duration = 10 * time.Second

	c := New(cfg)

	middleware.Setup(cfg)

	handler := resolver.New(cfg)
	ch := middleware.NewChain([]middleware.Handler{c, handler})

	ctxtest := context.Background()

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

	req = req.Copy()
	req.RecursionDesired = true
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("labs.example.com.", dns.TypeA)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeNameError, ch.Writer.Rcode())

	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("www.apple.com.", dns.TypeA)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	req = req.Copy()
	req.IsEdns0().SetUDPSize(512)
	req.SetQuestion("org.", dns.TypeDNSKEY)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	req = req.Copy()
	mw = mock.NewWriter("udp", "127.0.0.1:0")
	req.SetQuestion("www.microsoft.com.", dns.TypeCNAME)
	ch.Reset(mw, req)
	ch.Next(ctxtest)
	assert.True(t, mw.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())
}
