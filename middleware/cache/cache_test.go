package cache

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/semihalev/sdns/cache"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func Test_PCache(t *testing.T) {
	c := New(&config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1})
	assert.Equal(t, "cache", c.Name())

	dc := ctx.New([]ctx.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.ResetDNS(mw, req)

	q := req.Question[0]

	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	key := cache.Hash(q)
	_, found := c.get(key, now)
	assert.False(t, found)

	_, _, err := c.GetP(key, req)
	assert.Error(t, err)

	c.ServeDNS(dc)
	assert.False(t, dc.DNSWriter.Written())

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)
	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	c.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

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

	dc.ResetDNS(mw, req)
	c.ServeDNS(dc)
	assert.True(t, dc.DNSWriter.Written())

	dc.ResetDNS(mw, req)
	c.ServeDNS(dc)
	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeRefused, dc.DNSWriter.Rcode())

	req.IsEdns0().SetVersion(100)
	dc.ResetDNS(mw, req)
	c.ServeDNS(dc)
	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeBadVers, dc.DNSWriter.Rcode())

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	c.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)

	data, err := req.Pack()
	assert.NoError(t, err)

	dq := base64.RawURLEncoding.EncodeToString(data)

	request, err = http.NewRequest("GET", fmt.Sprintf("/dns-query?dns=%s", dq), nil)
	assert.NoError(t, err)

	hw = httptest.NewRecorder()
	dc.ResetHTTP(hw, request)
	c.ServeHTTP(dc)
	assert.Equal(t, 200, hw.Code)
}

func Test_NCache(t *testing.T) {
	c := New(&config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1})

	dc := ctx.New([]ctx.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.ResetDNS(mw, req)

	q := req.Question[0]

	now, _ := time.Parse(time.UnixDate, "Fri Apr 21 10:51:21 BST 2017")

	key := cache.Hash(q)

	err := c.GetN(key, req)
	assert.Error(t, err)

	msg := new(dns.Msg)
	msg.SetRcode(req, dns.RcodeNameError)
	msg.Ns = append(msg.Ns, makeRR("test.com.		1000000	IN	SOA	ns1.test.com. ns1.test.com. 118111607 10800 3600 604800 3600"))

	c.Set(key, msg)
	i, found := c.get(key, now)
	assert.True(t, found)
	assert.NotNil(t, i)

	err = c.GetN(key, req)
	assert.NoError(t, err)
}

func Test_Cache_RRSIG(t *testing.T) {
	c := New(&config.Config{Expire: 300, CacheSize: 10240, RateLimit: 1})

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
	c := New(&config.Config{Expire: 300, CacheSize: 10240, RateLimit: 10})

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

	dc := ctx.New([]ctx.Handler{})
	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)
	req.SetEdns0(4096, false)

	mw := mock.NewWriter("udp", "127.0.0.1")
	dc.ResetDNS(mw, req)
	c.ServeDNS(dc)
	assert.True(t, dc.DNSWriter.Written())
	assert.Equal(t, 3, len(dc.DNSWriter.Msg().Answer))

	c.now = func() time.Time {
		return time.Now().Add(time.Minute)
	}

	mw = mock.NewWriter("udp", "127.0.0.1")
	dc.ResetDNS(mw, req)
	c.ServeDNS(dc)
	assert.False(t, dc.DNSWriter.Written())
}
