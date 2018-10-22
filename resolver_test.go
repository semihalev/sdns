package main

import (
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_resolver(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	resp, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverDNSSEC(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("good.dnssec-or-not.com.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	resp, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverBadDNSSEC(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("dnssec-failed.org.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverBadKeyDNSSEC(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("bad.dnssec-or-not.com.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverExponentDNSSEC(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("sigfail.verteiltesysteme.net.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverDS(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("nic.cz.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	resp, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverDSDelegate(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("nic.co.id.", dns.TypeNS)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	resp, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverDSDFail(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("dnssec.fail.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNoSigner(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("b.in-addr.cn.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverAllNS(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("sds4wdwf.", dns.TypeNS)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverTimeout(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("baddns.com.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverLoop(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("153.218.66.36.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverRootServersDetect(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("12.137.53.1.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNameserverError(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("33.38.244.195.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNSEC3nodata(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("ns-lacnic.nic.mx.", dns.TypeDS)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNSECnodata(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("tr.", dns.TypeDS)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNSEC3nameerror(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("asdasdad3awds.eu.", dns.TypeA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverRootKeys(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeDNSKEY)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNoAnswer(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.sozcu.com.tr.", dns.TypeAAAA)
	req.SetEdns0(DefaultMsgSize, true)

	r := NewResolver()

	_, err := r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}
