// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package dnsutil

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/stretchr/testify/assert"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

func TestExtractAddressFromReverse(t *testing.T) {
	tests := []struct {
		reverseName     string
		expectedAddress string
	}{
		{
			"54.119.58.176.in-addr.arpa.",
			"176.58.119.54",
		},
		{
			".58.176.in-addr.arpa.",
			"",
		},
		{
			"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.in-addr.arpa.",
			"",
		},
		{
			"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
			"2001:db8::567:89ab",
		},
		{
			"d.0.1.0.0.2.ip6.arpa.",
			"",
		},
		{
			"54.119.58.176.ip6.arpa.",
			"",
		},
		{
			"NONAME",
			"",
		},
		{
			"",
			"",
		},
	}
	for i, test := range tests {
		got := ExtractAddressFromReverse(test.reverseName)
		if got != test.expectedAddress {
			t.Errorf("Test %d, expected '%s', got '%s'", i, test.expectedAddress, got)
		}
	}
}

func TestIsReverse(t *testing.T) {
	tests := []struct {
		name     string
		expected int
	}{
		{"b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.", 2},
		{"d.0.1.0.0.2.in-addr.arpa.", 1},
		{"example.com.", 0},
		{"", 0},
		{"in-addr.arpa.example.com.", 0},
	}
	for i, tc := range tests {
		got := IsReverse(tc.name)
		if got != tc.expected {
			t.Errorf("Test %d, got %d, expected %d for %s", i, got, tc.expected, tc.name)
		}

	}
}

func TestSetRcode(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.SetEdns0(4096, true)

	m := SetRcode(req, dns.RcodeServerFailure, true)
	if m.Rcode != dns.RcodeServerFailure {
		t.Errorf("Test HandleFailed, got %d, expected %d", m.Rcode, dns.RcodeServerFailure)
	}
}

func TestSetEnds0(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	size := 0

	opt, _, _, _, _ := SetEdns0(req)
	if opt == nil {
		t.Errorf("Test SetEdns0, got OPT nil")
	}

	opt, _, _, _, _ = SetEdns0(req)
	if opt == nil {
		t.Errorf("Test SetEdns0, got OPT nil")
	}

	opt.SetUDPSize(128)
	opt, size, _, _, _ = SetEdns0(req)
	if size != dns.MinMsgSize {
		t.Errorf("Test SetEdns0 size not equal with dns minimal size")
	}

	opt.SetVersion(100)
	opt, _, _, _, _ = SetEdns0(req)
	if opt.Version() != 100 {
		t.Errorf("Test edns version should be 100 expected %d", opt.Version())
	}

	/*opt.SetVersion(0)
	option := &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: 1, SourceNetmask: 32, SourceScope: 0, Address: net.ParseIP("127.0.0.1").To4()}
	opt.Option = append(opt.Option, option)
	opt, _, _, _ = SetEdns0(req)
	if len(opt.Option) != 1 {
		t.Errorf("Test edns option length should be 1 expected %d", len(opt.Option))
	}*/

	rr := makeRR("example.com. IN A 127.0.0.1")
	req.Extra = append(req.Extra, rr)
	req = ClearOPT(req)
	if len(req.Extra) != 1 {
		t.Errorf("Test req extra length should be 1 expected %d", len(req.Extra))
	}
}

func TestClearDNSSEC(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("miek.nl.", dns.TypeNS)

	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	NS	linode.atoom.net."))
	msg.Answer = append(msg.Answer, makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20181217031301 20181117031301 12051 miek.nl. rzrfC1x56DO660O+w1fJAqL+u6OYjDWaBoS6ZKSrUOXJOIO1rV8vV3v4 O6FvKXtbyBB3KpUEpN044D5C+dv0fNfJ4g0MYCAzHygCXRSmCY7d4yHO 73Im3jhQtxnlzSCSYHC4sMUc63TkOqftets+DmlE3VnWmlkq2qS3QNqW uto="))

	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	A	176.58.119.54"))
	msg.Ns = append(msg.Ns, makeRR("linode.atoom.net.	1800	IN	RRSIG	A 8 3 1800 20181217031301 20181117031301 53289 atoom.net. car2hvJmft8+sA3zgk1zb8gdL8afpTBmUYaYK1OJuB+B6508IZIAYCFc 4yNFjxOFC9PaQz1GsgKNtwYl1HF8SAO/kTaJgP5V8BsZLfOGsQi2TWhn 3qOkuA563DvehVdMIzqzCTK5sLiQ25jg6saTiHO0yjpYBgcIxYvf8YW9 KYU="))

	msg = ClearDNSSEC(msg)
	if len(msg.Answer) != 1 {
		t.Errorf("Test msg answer length should be 1 expected %d", len(msg.Extra))
	}

	if len(msg.Ns) != 1 {
		t.Errorf("Test msg ns length should be 1 expected %d", len(msg.Ns))
	}
}

func TestExchangeInternal(t *testing.T) {
	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"

	middleware.Setup(cfg)

	blocklist := middleware.Get("blocklist").(*blocklist.BlockList)
	blocklist.Set("example.com.")

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	msg, err := ExchangeInternal(context.Background(), req)
	if err != nil {
		t.Errorf("Test exchange internal should not be error")
		return
	}

	if len(msg.Answer) != 1 {
		t.Errorf("Test exchange internal return should be answer")
	}

	req.SetQuestion("www.example.com.", dns.TypeA)
	_, err = ExchangeInternal(context.Background(), req)
	if err == nil {
		t.Errorf("Test exchange internal should be error")
	}
}

func TestParsePurgeQuestion(t *testing.T) {
	req := new(dns.Msg)

	_, _, ok := ParsePurgeQuestion(req)
	assert.False(t, ok)

	req.SetQuestion("test.com.", dns.TypeNULL)
	_, _, ok = ParsePurgeQuestion(req)
	assert.False(t, ok)

	bstr := base64.StdEncoding.EncodeToString([]byte("test.com."))
	req.SetQuestion(bstr, dns.TypeNULL)
	_, _, ok = ParsePurgeQuestion(req)
	assert.False(t, ok)

	bstr = base64.StdEncoding.EncodeToString([]byte("ff:test.com."))
	req.SetQuestion(bstr, dns.TypeNULL)
	_, _, ok = ParsePurgeQuestion(req)
	assert.False(t, ok)

	bstr = base64.StdEncoding.EncodeToString([]byte("A:test.com."))
	req.SetQuestion(bstr, dns.TypeNULL)
	qname, qtype, ok := ParsePurgeQuestion(req)
	assert.True(t, ok)
	assert.Equal(t, "test.com.", qname)
	assert.Equal(t, dns.TypeA, qtype)
}
