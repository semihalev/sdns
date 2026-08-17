package resolver

import (
	"testing"

	"github.com/miekg/dns"
)

func leaderWithOPT() *dns.Msg {
	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	m.SetEdns0(1232, true)
	// Spare capacity behind an existing option: the shape where an
	// unprivatized keepalive append would land in shared backing.
	opt := m.IsEdns0()
	opt.Option = make([]dns.EDNS0, 1, 4)
	opt.Option[0] = &dns.EDNS0_NSID{Code: dns.EDNS0NSID}
	return m
}

// TestAcquireAttemptReqSharesRecordsOwnsBackings pins the per-attempt copy
// contract: header and question carry over into the shell's own backings —
// mutating the attempt never touches the leader — while the OPT record
// itself is shared by pointer.
func TestAcquireAttemptReqSharesRecordsOwnsBackings(t *testing.T) {
	leader := leaderWithOPT()

	att := acquireAttemptReq(leader)
	defer ReleaseMsg(att)

	if att.Question[0] != leader.Question[0] || att.MsgHdr != leader.MsgHdr {
		t.Fatal("header/question must carry over")
	}
	// The OPT shell is private — packing writes the extended rcode into
	// its header — while its options stay shared.
	if len(att.Extra) != 1 || att.Extra[0] == leader.Extra[0] {
		t.Fatal("the OPT shell must be private per attempt")
	}
	attOpt, leaderOpt := att.IsEdns0(), leader.IsEdns0()
	if attOpt.Hdr != leaderOpt.Hdr || attOpt.UDPSize() != leaderOpt.UDPSize() || attOpt.Do() != leaderOpt.Do() {
		t.Fatal("OPT shell contents must carry over")
	}
	if len(attOpt.Option) != 1 || attOpt.Option[0] != leaderOpt.Option[0] {
		t.Fatal("options must be shared by pointer")
	}
	attOpt.SetExtendedRcode(0xFF0)
	if leaderOpt.Hdr.Ttl == attOpt.Hdr.Ttl {
		t.Fatal("extended-rcode write leaked into the leader's OPT")
	}

	att.Id = 42
	att.Question[0].Name = "other.test."
	if leader.Id == 42 || leader.Question[0].Name != "example.com." {
		t.Fatal("attempt mutation leaked into the leader")
	}
}

// TestAcquireAttemptReqCarriesSections pins section parity with the deep
// copy it replaced: a leader carrying answer/authority/other-extra records
// hands them to the attempt shared by pointer.
func TestAcquireAttemptReqCarriesSections(t *testing.T) {
	leader := leaderWithOPT()
	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET}}
	soa := &dns.SOA{Hdr: dns.RR_Header{Name: "com.", Rrtype: dns.TypeSOA, Class: dns.ClassINET}, Ns: "a.", Mbox: "."}
	txt := &dns.TXT{Hdr: dns.RR_Header{Name: "x.", Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"y"}}
	leader.Answer = []dns.RR{a}
	leader.Ns = []dns.RR{soa}
	leader.Extra = append(leader.Extra, txt)

	att := acquireAttemptReq(leader)
	defer ReleaseMsg(att)

	if len(att.Answer) != 1 || att.Answer[0] != dns.RR(a) {
		t.Fatal("answer section must carry over shared")
	}
	if len(att.Ns) != 1 || att.Ns[0] != dns.RR(soa) {
		t.Fatal("authority section must carry over shared")
	}
	if len(att.Extra) != 2 || att.Extra[1] != dns.RR(txt) {
		t.Fatal("non-OPT extra must carry over shared")
	}
}

// TestPrivatizeOPTIsolatesKeepalive pins the TCP leg's copy-on-write: after
// privatizeOPT, the keepalive append lands on a private OPT and the
// leader's option list stays untouched.
func TestPrivatizeOPTIsolatesKeepalive(t *testing.T) {
	leader := leaderWithOPT()
	att := acquireAttemptReq(leader)
	defer ReleaseMsg(att)

	privatizeOPT(att)
	if att.Extra[0] == leader.Extra[0] {
		t.Fatal("privatizeOPT must replace the shared OPT")
	}
	if att.IsEdns0().Option[0] == leader.IsEdns0().Option[0] {
		t.Fatal("privatizeOPT must deep-copy the options")
	}

	// The leader's option backing has spare capacity behind its one
	// option — exactly where an unprivatized append would land.
	spare := leader.IsEdns0().Option[:2]

	SetEDNSKeepalive(att, 0)
	if len(att.IsEdns0().Option) != 2 {
		t.Fatal("keepalive not appended to the attempt's OPT")
	}
	if len(leader.IsEdns0().Option) != 1 || spare[1] != nil {
		t.Fatal("keepalive contaminated the leader's OPT backing")
	}
	if !leader.IsEdns0().Do() {
		t.Fatal("leader OPT flags disturbed")
	}
}

// BenchmarkAttemptCopy compares the per-server view against the full deep
// copy it replaced.
func BenchmarkAttemptCopy(b *testing.B) {
	leader := leaderWithOPT()

	b.Run("acquireAttemptReq", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ReleaseMsg(acquireAttemptReq(leader))
		}
	})
	b.Run("CopyTo", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ReleaseMsg(leader.CopyTo(AcquireMsg()))
		}
	})
}

// TestAcquireAttemptReqAllocatesNothing pins the point: after the pool
// warms, a per-server attempt view costs zero heap allocations.
func TestAcquireAttemptReqAllocatesNothing(t *testing.T) {
	leader := leaderWithOPT()

	// Warm one shell so its backings exist.
	ReleaseMsg(acquireAttemptReq(leader))

	// dns.Id stays out of the loop: it allocates its own 2-byte buffer
	// inside binary.Read, a pre-existing per-attempt cost this test does
	// not own. The one allocation left is the private OPT shell —
	// packing writes into the OPT header, so attempts cannot share it.
	if n := testing.AllocsPerRun(100, func() {
		att := acquireAttemptReq(leader)
		att.Id = 42
		ReleaseMsg(att)
	}); n != 1 {
		t.Fatalf("allocs = %v, want exactly the OPT shell", n)
	}
}
