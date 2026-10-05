package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	cachemw "github.com/semihalev/sdns/middleware/cache"
)

func newBlockAAAAServer(tb testing.TB, configure func(*config.Config)) *Server {
	tb.Helper()
	return newHitChainServerConfigured(tb, nil, func(cfg *config.Config) {
		cfg.BlockAAAA = true
		if configure != nil {
			configure(cfg)
		}
	})
}

func blockAAAAQuery(tb testing.TB, id uint16, withEDNS bool) (*dns.Msg, []byte) {
	tb.Helper()
	q := new(dns.Msg)
	q.SetQuestion("policy.example.", dns.TypeAAAA)
	q.Id = id
	q.RecursionDesired = true
	q.CheckingDisabled = true
	if withEDNS {
		q.SetEdns0(1232, true)
	}
	raw, err := q.Pack()
	if err != nil {
		tb.Fatalf("pack query: %v", err)
	}
	return q, raw
}

func assertBlockAAAANODATA(tb testing.TB, got, want *dns.Msg, withEDNS bool) {
	tb.Helper()
	if got.Id != want.Id || !got.Response || got.Opcode != want.Opcode || got.Rcode != dns.RcodeSuccess {
		tb.Fatalf("header = id:%d qr:%v opcode:%d rcode:%s, want id:%d QR NOERROR",
			got.Id, got.Response, got.Opcode, dns.RcodeToString[got.Rcode], want.Id)
	}
	if len(got.Question) != 1 || got.Question[0] != want.Question[0] {
		tb.Fatalf("question = %v, want %v", got.Question, want.Question)
	}
	if got.Authoritative || got.AuthenticatedData || !got.RecursionAvailable || !got.RecursionDesired || !got.CheckingDisabled {
		tb.Fatalf("flags = AA:%v AD:%v RA:%v RD:%v CD:%v, want false false true true true",
			got.Authoritative, got.AuthenticatedData, got.RecursionAvailable, got.RecursionDesired, got.CheckingDisabled)
	}
	if len(got.Answer) != 0 || len(got.Ns) != 0 {
		tb.Fatalf("NODATA sections = answer:%v authority:%v, want empty", got.Answer, got.Ns)
	}
	opt := got.IsEdns0()
	if !withEDNS {
		if opt != nil {
			tb.Fatalf("reply OPT = %v, want none without client EDNS", opt)
		}
		return
	}
	if opt == nil || opt.Version() != 0 || opt.UDPSize() != 1232 || !opt.Do() {
		tb.Fatalf("reply OPT = %v, want EDNS0 size 1232 with DO", opt)
	}
	var ede *dns.EDNS0_EDE
	for _, option := range opt.Option {
		if e, ok := option.(*dns.EDNS0_EDE); ok {
			ede = e
			break
		}
	}
	if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeOther || ede.ExtraText != "AAAA response suppressed by policy" {
		tb.Fatalf("reply EDE = %v, want Other with policy text", ede)
	}
}

func seedBlockAAAAHit(tb testing.TB, s *Server, q *dns.Msg) {
	tb.Helper()
	c, ok := middleware.Get("cache").(*cachemw.Cache)
	if !ok {
		tb.Fatalf("default chain has no cache")
	}
	resp := new(dns.Msg)
	resp.SetReply(q)
	resp.RecursionAvailable = true
	resp.Answer = []dns.RR{&dns.AAAA{
		Hdr:  dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
		AAAA: net.ParseIP("2001:db8::53"),
	}}
	c.Set(cachemw.CacheKey{Question: q.Question[0], CD: q.CheckingDisabled}.Hash(), resp)
}

func TestBlockAAAASuppressesStrictWarmCacheAndInline(t *testing.T) {
	s := newBlockAAAAServer(t, nil)
	q, raw := blockAAAAQuery(t, 0x53a1, true)
	seedBlockAAAAHit(t, s, q)

	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 53), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("strict raw serve did not handle the query")
	}
	if job.req.Raw() == nil {
		t.Fatal("strict raw serve fell back to decoded ingress")
	}
	got := new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatalf("unpack strict reply: %v", err)
	}
	assertBlockAAAANODATA(t, got, q, true)
	if len(got.Answer) != 0 {
		t.Fatalf("warm cached AAAA answer bypassed policy: %v", got.Answer)
	}

	job.wrote = job.wrote[:0]
	if !s.ServeRawInline(job, raw, time.Now()) {
		t.Fatal("inline serve did not finish the eligible AAAA suppression")
	}
	got = new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatalf("unpack inline reply: %v", err)
	}
	assertBlockAAAANODATA(t, got, q, true)

	qNoEDNS, rawNoEDNS := blockAAAAQuery(t, 0x53a3, false)
	job.wrote = job.wrote[:0]
	if !s.ServeRaw(job, rawNoEDNS, time.Now()) {
		t.Fatal("no-EDNS strict serve did not handle the query")
	}
	got = new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatalf("unpack no-EDNS reply: %v", err)
	}
	assertBlockAAAANODATA(t, got, qNoEDNS, false)
}

func TestBlockAAAAServesNODATAAcrossOwnedTransports(t *testing.T) {
	for _, proto := range []string{"udp", "tcp", "dot", "doh", "doq"} {
		t.Run(proto, func(t *testing.T) {
			s := newBlockAAAAServer(t, nil)
			certs := &fakeCerts{cfg: minimalTLSConfig(t)}
			var listener Listener
			switch proto {
			case "udp":
				listener = newUDPListener([]string{"127.0.0.1:0"}, s, time.Second, 2, 16, defaultResourcePlan(1))
			case "tcp":
				listener = newTCPListener([]string{"127.0.0.1:0"}, s, time.Second, 8, defaultResourcePlan(1))
			case "dot":
				listener = newTLSListener([]string{"127.0.0.1:0"}, s, certs, time.Second, 8, defaultResourcePlan(1))
			case "doh":
				listener = newDOHListener([]string{"127.0.0.1:0"}, s, certs, time.Second)
			}
			if proto != "doq" {
				addr := serveListener(t, listener)[0]
				q, wire := blockAAAAQuery(t, 0x53a2, true)
				var got *dns.Msg
				switch proto {
				case "udp", "tcp", "dot":
					netName := proto
					if proto == "dot" {
						netName = "tcp-tls"
					}
					client := &dns.Client{Net: netName, Timeout: 3 * time.Second}
					if proto == "dot" {
						client.TLSConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // loopback test server
					}
					response, _, err := client.Exchange(q, addr)
					if err != nil {
						t.Fatalf("%s exchange: %v", proto, err)
					}
					got = response
				case "doh":
					request, err := http.NewRequest(http.MethodPost, "https://"+addr+"/dns-query", bytes.NewReader(wire))
					if err != nil {
						t.Fatal(err)
					}
					request.Header.Set("Content-Type", "application/dns-message")
					transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}} //nolint:gosec // loopback test server
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
					response, err := client.Do(request)
					if err != nil {
						t.Fatalf("DoH exchange: %v", err)
					}
					defer response.Body.Close()
					if response.StatusCode != http.StatusOK {
						t.Fatalf("DoH HTTP status = %d, want 200", response.StatusCode)
					}
					body, err := io.ReadAll(response.Body)
					if err != nil {
						t.Fatalf("read DoH reply: %v", err)
					}
					got = new(dns.Msg)
					if err := got.Unpack(body); err != nil {
						t.Fatalf("unpack DoH reply: %v", err)
					}
				}
				assertBlockAAAANODATA(t, got, q, true)
				return
			}

			_, addr := startDoQ(t, s, doqPlan(4, 4))
			conn, err := dialDoQ(t, addr)
			if err != nil {
				t.Fatal(err)
			}
			q, wire := blockAAAAQuery(t, 0, true)
			if len(wire) > 0xffff {
				t.Fatalf("DoQ query length = %d, exceeds the 16-bit frame limit", len(wire))
			}
			frameLen := uint16(len(wire)) //nolint:gosec // the explicit 16-bit bound check above makes this safe
			framed := binary.BigEndian.AppendUint16(nil, frameLen)
			framed = append(framed, wire...)
			got, err := exchange(conn, framed, false)
			if err != nil {
				t.Fatalf("DoQ exchange: %v", err)
			}
			assertBlockAAAANODATA(t, got, q, true)
		})
	}
}

func TestBlockAAAAKeepsCookiePaddingAndEDEOnDoT(t *testing.T) {
	s := newBlockAAAAServer(t, nil)
	certs := &fakeCerts{cfg: minimalTLSConfig(t)}
	listener := newTLSListener([]string{"127.0.0.1:0"}, s, certs, time.Second, 8, defaultResourcePlan(1))
	addr := serveListener(t, listener)[0]

	q, _ := blockAAAAQuery(t, 0x53a7, false)
	q.SetEdns0(1232, true)
	opt := q.IsEdns0()
	opt.Option = append(opt.Option,
		&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"},
		&dns.EDNS0_PADDING{Padding: make([]byte, 64)},
	)
	client := &dns.Client{
		Net:       "tcp-tls",
		Timeout:   3 * time.Second,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // loopback test server
	}
	got, _, err := client.Exchange(q, addr)
	if err != nil {
		t.Fatalf("DoT exchange: %v", err)
	}
	assertBlockAAAANODATA(t, got, q, true)

	var cookie *dns.EDNS0_COOKIE
	hasPadding := false
	for _, option := range got.IsEdns0().Option {
		switch value := option.(type) {
		case *dns.EDNS0_COOKIE:
			cookie = value
		case *dns.EDNS0_PADDING:
			hasPadding = true
		}
	}
	if cookie == nil || !strings.HasPrefix(cookie.Cookie, "0102030405060708") || len(cookie.Cookie) <= 16 {
		t.Fatalf("reply COOKIE = %v, want the client's cookie plus a server cookie", cookie)
	}
	if !hasPadding {
		t.Fatal("encrypted reply omitted requested padding")
	}
	wire, err := got.Pack()
	if err != nil {
		t.Fatalf("pack DoT reply: %v", err)
	}
	if len(wire)%468 != 0 {
		t.Fatalf("padded DoT reply length = %d, want a multiple of 468", len(wire))
	}
}

func TestBlockAAAAChainPrecedenceWithDNS64(t *testing.T) {
	var resolverCalls int
	s := newHitChainServerConfigured(t, func(req *dns.Msg) *dns.Msg {
		resolverCalls++
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		if req.Question[0].Qtype == dns.TypeA {
			resp.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60}, A: net.IPv4(192, 0, 2, 55)}}
		}
		return resp
	}, func(cfg *config.Config) {
		cfg.BlockAAAA = true
		cfg.DNS64.Enabled = true
		cfg.DNS64.Prefixes = []string{"64:ff9b::/96"}
		hosts := filepath.Join(t.TempDir(), "hosts")
		if err := os.WriteFile(hosts, []byte("2001:db8::1 policy.example\n"), 0600); err != nil {
			t.Fatalf("write hosts fixture: %v", err)
		}
		cfg.HostsFile = hosts
		cfg.Views = []config.ViewConfig{{
			Zone:     "local",
			Networks: []string{"203.0.113.0/24"},
			Answers:  []string{"policy.example. 60 IN AAAA 2001:db8::2"},
		}}
		cfg.RPZ.Enabled = true
	})

	indices := make(map[string]int)
	for i, h := range s.pipeline.Handlers() {
		indices[h.Name()] = i
	}
	if indices["ddr"] >= indices["block_aaaa"] ||
		indices["block_aaaa"] >= indices["hostsfile"] ||
		indices["hostsfile"] >= indices["views"] ||
		indices["views"] >= indices["dns64"] ||
		indices["block_aaaa"] >= indices["rpz"] {
		t.Fatalf("default-chain positions = ddr:%d block_aaaa:%d hostsfile:%d views:%d rpz:%d dns64:%d",
			indices["ddr"], indices["block_aaaa"], indices["hostsfile"], indices["views"], indices["rpz"], indices["dns64"])
	}

	q, raw := blockAAAAQuery(t, 0x53a4, true)
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 55), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("serve did not handle DNS64 coexistence query")
	}
	got := new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatalf("unpack DNS64 coexistence reply: %v", err)
	}
	assertBlockAAAANODATA(t, got, q, true)
	if resolverCalls != 0 {
		t.Fatalf("resolver calls = %d, want 0 when suppression precedes DNS64/cache", resolverCalls)
	}
}

func TestBlockAAAAInternalSubqueryKeepsAAAA(t *testing.T) {
	s := newHitChainServerConfigured(t, func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: req.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.ParseIP("2001:db8::55"),
		}}
		return resp
	}, func(cfg *config.Config) {
		cfg.BlockAAAA = true
	})
	var clientOnly []string
	for _, h := range s.pipeline.Handlers() {
		if co, ok := h.(middleware.ClientOnly); ok && co.ClientOnly() {
			clientOnly = append(clientOnly, h.Name())
		}
	}
	internal := middleware.NewPipelineQueryer(s.pipeline.SubPipeline(clientOnly...))
	q, _ := blockAAAAQuery(t, 0x53a6, false)
	resp, err := internal.Query(context.Background(), q)
	if err != nil {
		t.Fatalf("internal AAAA query: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != dns.TypeAAAA {
		t.Fatalf("internal AAAA response = %v, want one AAAA answer", resp)
	}
}

func TestBlockAAAAPreservesACLAndMalformedIngress(t *testing.T) {
	s := newBlockAAAAServer(t, func(cfg *config.Config) {
		cfg.AccessList = []string{"10.0.0.0/8"}
	})
	_, raw := blockAAAAQuery(t, 0x53a5, true)
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 56), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("ACL query was not accepted by ingress")
	}
	if len(job.wrote) != 0 {
		t.Fatalf("ACL-denied AAAA query received a policy answer: %d bytes", len(job.wrote))
	}

	malformed := new(dns.Msg)
	malformed.SetQuestion("malformed.example.", dns.TypeAAAA)
	malformed.Question = append(malformed.Question, dns.Question{Name: "second.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET})
	badRaw, err := malformed.Pack()
	if err != nil {
		t.Fatalf("pack malformed request: %v", err)
	}
	job.wrote = job.wrote[:0]
	if !s.ServeRaw(job, badRaw, time.Now()) {
		t.Fatal("decodable malformed request was not handled")
	}
	got := new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatalf("unpack malformed response: %v", err)
	}
	if got.Rcode != dns.RcodeFormatError {
		t.Fatalf("malformed request rcode = %s, want FORMERR", dns.RcodeToString[got.Rcode])
	}
}

func TestBlockAAAAARecordWarmHitAllocatesNothing(t *testing.T) {
	for _, withEDNS := range []bool{false, true} {
		t.Run(map[bool]string{false: "noopt", true: "edns"}[withEDNS], func(t *testing.T) {
			s := newBlockAAAAServer(t, nil)
			m := new(dns.Msg)
			m.SetQuestion("alloc.block-aaaa.test.", dns.TypeA)
			if withEDNS {
				m.SetEdns0(1232, true)
			}
			raw, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 57), Port: 4242}}
			for range 2 {
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("warm serve not handled")
				}
			}
			got := new(dns.Msg)
			if err := got.Unpack(job.wrote); err != nil {
				t.Fatalf("unpack A reply: %v", err)
			}
			if len(got.Answer) != 1 || got.Answer[0].Header().Rrtype != dns.TypeA {
				t.Fatalf("A query answer = %v, want one A record", got.Answer)
			}
			if allocs := testing.AllocsPerRun(500, func() {
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("hit serve not handled")
				}
			}); allocs != 0 {
				t.Fatalf("warm A hit allocated %.2f objects per serve, want 0", allocs)
			}
		})
	}
}

// Repeated use of one job must echo only the current query. Concurrent jobs
// must not share response storage or inherit another client's EDNS/flags.
func TestBlockAAAARawReuseAndConcurrentJobs(t *testing.T) {
	s := newBlockAAAAServer(t, nil)
	var wg sync.WaitGroup
	for _, worker := range []byte{1, 2, 3, 4} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, worker), Port: 4242}}
			for i := range uint16(40) {
				m := new(dns.Msg)
				m.SetQuestion(fmt.Sprintf("MiXeD-%d-%d.block-aaaa.test.", worker, i), dns.TypeAAAA)
				m.Id = uint16(worker)*100 + i
				m.RecursionDesired, m.CheckingDisabled = i%2 == 0, i%3 == 0
				if i%2 == 0 {
					m.SetEdns0(1232, i%4 == 0)
				}
				raw, err := m.Pack()
				if err != nil {
					t.Error(err)
					return
				}
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Error("serve not handled")
					return
				}
				got := new(dns.Msg)
				if err := got.Unpack(job.wrote); err != nil {
					t.Error(err)
					return
				}
				if got.Id != m.Id || len(got.Question) != 1 || got.Question[0] != m.Question[0] ||
					got.RecursionDesired != m.RecursionDesired || got.CheckingDisabled != m.CheckingDisabled ||
					got.Authoritative || got.AuthenticatedData || !got.RecursionAvailable ||
					len(got.Answer) != 0 || len(got.Ns) != 0 || got.Rcode != dns.RcodeSuccess {
					t.Errorf("reused job reply differs: %v / %v", got, m)
					return
				}
				if (got.IsEdns0() != nil) != (m.IsEdns0() != nil) {
					t.Error("EDNS leaked between queries")
					return
				}
				if got.IsEdns0() != nil && got.IsEdns0().Do() != m.IsEdns0().Do() {
					t.Error("DO leaked between queries")
					return
				}
			}
		}()
	}
	wg.Wait()
}

func BenchmarkBlockAAAAServeRaw(b *testing.B) {
	for _, useEDNS := range []bool{false, true} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			name := "A warm hit"
			if qtype == dns.TypeAAAA {
				name = "AAAA NODATA"
			}
			b.Run(fmt.Sprintf("%s/edns=%v", name, useEDNS), func(b *testing.B) {
				s := newBlockAAAAServer(b, nil)
				m := new(dns.Msg)
				m.SetQuestion("bench.block-aaaa.test.", qtype)
				if useEDNS {
					m.SetEdns0(1232, false)
				}
				raw, err := m.Pack()
				if err != nil {
					b.Fatal(err)
				}
				job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 54), Port: 4242}}
				for range 2 {
					if !s.ServeRaw(job, raw, time.Now()) {
						b.Fatal("warm serve not handled")
					}
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if !s.ServeRaw(job, raw, time.Now()) {
						b.Fatal("serve not handled")
					}
				}
			})
		}
	}
}

// An OPT too large for the byte preflight must retake the ordinary EDNS
// truncation path, which drops EDE before other data. It still suppresses
// AAAA and never forwards a policy query.
func TestBlockAAAARawOversizedNSIDFallback(t *testing.T) {
	calls := 0
	s := newHitChainServerConfigured(t, func(q *dns.Msg) *dns.Msg {
		calls++
		resp := new(dns.Msg)
		resp.SetReply(q)
		return resp
	}, func(cfg *config.Config) { cfg.BlockAAAA = true; cfg.NSID = strings.Repeat("x", 600) })
	m := new(dns.Msg)
	m.SetQuestion("oversized.block-aaaa.test.", dns.TypeAAAA)
	m.SetEdns0(512, true)
	m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_NSID{Code: dns.EDNS0NSID}}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 54), Port: 4242}}
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("serve not handled")
	}
	got := new(dns.Msg)
	if err := got.Unpack(job.wrote); err != nil {
		t.Fatal(err)
	}
	if !got.Truncated || got.Rcode != dns.RcodeSuccess || len(got.Answer) != 0 || len(got.Ns) != 0 || got.AuthenticatedData {
		t.Fatalf("fallback reply = %v", got)
	}
	if calls != 0 {
		t.Fatal("oversized policy reply reached downstream")
	}
}
