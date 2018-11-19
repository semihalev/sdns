package resolver

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/middleware/edns"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

func makeTestConfig() *config.Config {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.RootServers = []string{"192.5.5.241:53"}
	cfg.RootKeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=",
		".			172800	IN	DNSKEY	256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=",
	}
	cfg.Maxdepth = 30
	cfg.Expire = 600
	cfg.CacheSize = 1024
	cfg.Timeout.Duration = 2 * time.Second
	cfg.ConnectTimeout.Duration = 2 * time.Second

	return cfg
}

func RunLocalUDPServer(laddr string) (*dns.Server, string, error) {
	server, l, _, err := RunLocalUDPServerWithFinChan(laddr)

	return server, l, err
}

func RunLocalUDPServerWithFinChan(laddr string, opts ...func(*dns.Server)) (*dns.Server, string, chan error, error) {
	pc, err := net.ListenPacket("udp4", laddr)
	if err != nil {
		return nil, "", nil, err
	}
	server := &dns.Server{PacketConn: pc, ReadTimeout: time.Hour, WriteTimeout: time.Hour}

	waitLock := sync.Mutex{}
	waitLock.Lock()
	server.NotifyStartedFunc = waitLock.Unlock

	// fin must be buffered so the goroutine below won't block
	// forever if fin is never read from. This always happens
	// in RunLocalUDPServer and can happen in TestShutdownUDP.
	fin := make(chan error, 1)

	for _, opt := range opts {
		opt(server)
	}

	go func() {
		fin <- server.ActivateAndServe()
		pc.Close()
	}()

	waitLock.Lock()
	return server, pc.LocalAddr().String(), fin, nil
}

func makeTestHandler(handler ctx.Handler) {
	edns := edns.New(nil)

	dns.DefaultServeMux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		dc := ctx.New([]ctx.Handler{edns, handler})
		dc.ResetDNS(w, req)
		dc.NextDNS()
	})
}

func Test_handler(t *testing.T) {
	cfg := makeTestConfig()
	handler := New(cfg)
	makeTestHandler(handler)

	time.Sleep(2 * time.Second)

	assert.Equal(t, "resolver", handler.Name())

	c := new(dns.Client)
	c.ReadTimeout = 15 * time.Second
	c.WriteTimeout = 15 * time.Second

	m := new(dns.Msg)
	m.RecursionDesired = true

	m.SetQuestion("www.apple.com.", dns.TypeA)
	r := handler.handle("udp", m)
	assert.Equal(t, len(r.Answer) > 0, true)

	// test again for caches
	m.SetQuestion("www.apple.com.", dns.TypeA)
	r = handler.handle("udp", m)
	assert.Equal(t, len(r.Answer) > 0, true)

	m.SetEdns0(dnsutil.DefaultMsgSize, true)
	m.SetQuestion("dnssec-failed.org.", dns.TypeA)
	r = handler.handle("udp", m)
	assert.Equal(t, len(r.Answer) == 0, true)

	m.SetQuestion("example.com.", dns.TypeA)
	r = handler.handle("udp", m)
	assert.Equal(t, len(r.Answer) > 0, true)

	m.SetQuestion(".", dns.TypeANY)
	r = handler.handle("udp", m)
	assert.Equal(t, r.Rcode, dns.RcodeNotImplemented)

	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = false
	r = handler.handle("udp", m)
	assert.NotEqual(t, r.Rcode, dns.RcodeServerFailure)
}

func Test_HandlerHINFO(t *testing.T) {
	cfg := makeTestConfig()
	handler := New(cfg)

	m := new(dns.Msg)
	m.SetQuestion(".", dns.TypeHINFO)

	debugns = true
	resp := handler.handle("udp", m)

	assert.Equal(t, true, len(resp.Ns) > 0)
}

func Test_HandlerServe(t *testing.T) {
	cfg := makeTestConfig()
	h := New(cfg)

	dc := ctx.New([]ctx.Handler{})
	mw := mock.NewWriter("udp", "127.0.0.1:0")
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	dc.ResetDNS(mw, req)

	h.ServeDNS(dc)
	assert.Equal(t, true, dc.DNSWriter.Written())
}
