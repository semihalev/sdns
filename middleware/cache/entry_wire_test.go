package cache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestCacheEntryWireRoundTrip pins the packed representation's serve
// fidelity: everything the parsed entry preserved must survive the
// pack-at-admission / unpack-at-serve round trip.
func TestCacheEntryWireRoundTrip(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("WWW.Example.COM.", dns.TypeA)
	req.Id = 4242
	req.SetEdns0(1232, true)

	src := new(dns.Msg)
	src.SetReply(req)
	src.Rcode = dns.RcodeSuccess
	src.AuthenticatedData = true
	src.RecursionAvailable = true
	src.Answer = append(src.Answer,
		makeRR("www.example.com. 300 IN CNAME edge.example.net."),
		makeRR("edge.example.net. 60 IN A 192.0.2.7"),
		makeRR("edge.example.net. 60 IN RRSIG A 13 3 60 20370101000000 20260101000000 7 example.net. ZmFrZXNpZ25hdHVyZQ=="),
	)
	src.Ns = append(src.Ns,
		makeRR("example.net. 120 IN NS ns1.example.net."),
	)
	opt := new(dns.OPT)
	opt.Hdr.Name = "."
	opt.Hdr.Rrtype = dns.TypeOPT
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeStaleAnswer,
		ExtraText: "pinned",
	})
	src.Extra = append(src.Extra, opt)

	entry := NewCacheEntryWithKey(src, 90*time.Second, 0, 1)
	if entry == nil {
		t.Fatal("packable message was rejected at admission")
	}

	resp := entry.ToMsg(req)
	if resp == nil {
		t.Fatal("fresh entry did not serve")
	}
	if resp.Id != req.Id || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("header = id %d rcode %d", resp.Id, resp.Rcode)
	}
	if !resp.AuthenticatedData || resp.Authoritative {
		t.Fatalf("flags: ad=%v aa=%v", resp.AuthenticatedData, resp.Authoritative)
	}
	if got := resp.Question[0].Name; got != "WWW.Example.COM." {
		t.Fatalf("question case = %q, want client spelling", got)
	}
	if len(resp.Answer) != 3 || len(resp.Ns) != 1 {
		t.Fatalf("sections = %d/%d answers/ns, want 3/1", len(resp.Answer), len(resp.Ns))
	}
	for i, want := range []string{
		"www.example.com.\t", "edge.example.net.\t", "edge.example.net.\t",
	} {
		if got := resp.Answer[i].String(); got[:len(want)] != want {
			t.Fatalf("answer[%d] = %q", i, got)
		}
		if resp.Answer[i].Header().Ttl != resp.Answer[0].Header().Ttl {
			t.Fatal("TTLs are not uniform")
		}
	}
	// The stored OPT was stripped; the EDE must be re-attached because the
	// client sent EDNS.
	respOpt := resp.IsEdns0()
	if respOpt == nil {
		t.Fatal("EDE carrier OPT missing for an EDNS client")
	}
	foundEDE := false
	for _, option := range respOpt.Option {
		if ede, ok := option.(*dns.EDNS0_EDE); ok &&
			ede.InfoCode == dns.ExtendedErrorCodeStaleAnswer {
			foundEDE = true
		}
	}
	if !foundEDE {
		t.Fatal("preserved EDE was not restored on serve")
	}

	// CD=1 request must never receive AD.
	cdReq := req.Copy()
	cdReq.CheckingDisabled = true
	if cd := entry.ToMsg(cdReq); cd == nil || cd.AuthenticatedData {
		t.Fatal("CD=1 serve kept the AD bit")
	}
}
