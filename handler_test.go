package main

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

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

func Test_handler(t *testing.T) {
	var err error

	Config.OutboundIPs, err = findLocalIPAddresses()
	assert.NoError(t, err)

	for i, ip := range Config.OutboundIPs {
		if ip == "127.0.0.1" {
			Config.OutboundIPs = append(Config.OutboundIPs[:i], Config.OutboundIPs[i+1:]...)
			break
		}
	}

	handler := NewHandler()

	dns.HandleFunc(".", handler.UDP)
	defer dns.HandleRemove(".")

	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	assert.NoError(t, err)

	defer s.Shutdown()

	c := new(dns.Client)
	c.ReadTimeout = 15 * time.Second
	c.WriteTimeout = 15 * time.Second

	m := new(dns.Msg)
	m.SetQuestion("www.google.com.", dns.TypeA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) > 0, true)

	// test again for caches
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) > 0, true)

	m.SetQuestion("www.apple.com.", dns.TypeA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) > 0, true)

	// test again for caches
	m.SetQuestion("www.apple.com.", dns.TypeA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) > 0, true)

	BlockList.Set("example.com.")

	m.SetQuestion("example.com.", dns.TypeA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)

	a := r.Answer[0].(*dns.A)
	assert.Equal(t, a.A.String(), "0.0.0.0")

	m.SetQuestion("example.com.", dns.TypeAAAA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)

	aaaa := r.Answer[0].(*dns.AAAA)
	assert.Equal(t, aaaa.AAAA.String(), "::")

	m.SetEdns0(DefaultMsgSize, true)
	m.SetQuestion("dnssec-failed.org.", dns.TypeA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) == 0, true)

	m.SetQuestion("example.com.", dns.TypeA)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, len(r.Answer) > 0, true)

	m.SetQuestion(".", dns.TypeANY)
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.Equal(t, r.Rcode, dns.RcodeNotImplemented)

	m.SetQuestion(".", dns.TypeNS)
	m.RecursionDesired = false
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.NotEqual(t, r.Rcode, dns.RcodeServerFailure)

	m.RecursionDesired = true
	m.SetEdns0(DefaultMsgSize, true)
	opt := m.IsEdns0()
	opt.SetVersion(100)
	opt.SetDo()
	r, _, err = c.Exchange(m, addrstr)
	assert.NoError(t, err)
	assert.NotEqual(t, r.Rcode, dns.RcodeBadVers)
}
