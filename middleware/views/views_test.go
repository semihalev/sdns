package views

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

// makeChain wires up a single-handler chain pointed at the view
// under test, with a mock writer addressed from clientAddr and a
// pre-populated request.
func makeChain(handler middleware.Handler, clientAddr, qname string, qtype uint16) *middleware.Chain {
	ch := middleware.NewChain([]middleware.Handler{handler})
	mw := mock.NewWriter("udp", clientAddr)
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(qname), qtype)
	ch.Reset(mw, req)
	return ch
}

func TestViews_NoConfig_FallsThrough(t *testing.T) {
	v := New(&config.Config{})
	ch := makeChain(v, "8.8.8.8:0", "example.com.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	if ch.Writer.Written() {
		t.Errorf("%s: ch.Writer.Written() is true", "no view configured: nothing should be written")
	}
}

func TestViews_MatchesClientCIDRAndWildcard(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers: []string{
			"*.birb.it. 60 IN A 192.168.1.3",
			"*.birb.it. 60 IN AAAA 2003:f5:6722::3",
		},
	}}}
	v := New(cfg)

	// Client inside the view's CIDR querying a wildcard-covered name.
	ch := makeChain(v, "192.168.1.42:5353", "foo.birb.it.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	if !(ch.Writer.Written()) {
		t.Errorf("%s: ch.Writer.Written() is false", "matching view must write a reply")
	}
	resp := ch.Writer.Msg()
	if len(resp.Answer) != 1 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
	}
	a, ok := resp.Answer[0].(*dns.A)
	if !(ok) {
		t.Errorf("ok is false")
	}
	if !reflect.DeepEqual("foo.birb.it.", a.Hdr.Name) {
		t.Errorf("%s: a.Hdr.Name = %v, want %v", "owner name in response must be the query name, not the wildcard", a.Hdr.Name, "foo.birb.it.")
	}
	if !reflect.DeepEqual("192.168.1.3", a.A.String()) {
		t.Errorf("a.A.String() = %v, want %v", a.A.String(), "192.168.1.3")
	}
	if !(resp.Authoritative) {
		t.Errorf("resp.Authoritative is false")
	}
}

func TestViews_QtypeMissingFallsThrough(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers:  []string{"*.birb.it. 60 IN A 192.168.1.3"},
	}}}
	v := New(cfg)

	// Client matches the view, name matches the wildcard, but the
	// view has no AAAA record for *.birb.it. The handler should
	// fall through (no answer written) so the resolver can take
	// over.
	ch := makeChain(v, "192.168.1.42:5353", "foo.birb.it.", dns.TypeAAAA)
	v.ServeDNS(context.Background(), ch)
	if ch.Writer.Written() {
		t.Errorf("%s: ch.Writer.Written() is true", "matched-view-but-no-record must fall through")
	}
}

func TestViews_ClientOutsideAllViewsFallsThrough(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers:  []string{"*.birb.it. 60 IN A 192.168.1.3"},
	}}}
	v := New(cfg)
	ch := makeChain(v, "8.8.8.8:5353", "foo.birb.it.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	if ch.Writer.Written() {
		t.Errorf("ch.Writer.Written() is true")
	}
}

func TestViews_FirstMatchWins(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{
		{
			Zone:     "vpnnet",
			Networks: []string{"100.64.0.0/24"},
			Answers:  []string{"*.birb.it. 60 IN A 100.64.0.2"},
		},
		{
			Zone:     "lannet",
			Networks: []string{"192.168.1.0/24"},
			Answers:  []string{"*.birb.it. 60 IN A 192.168.1.3"},
		},
	}}
	v := New(cfg)

	ch := makeChain(v, "100.64.0.5:5353", "foo.birb.it.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	resp := ch.Writer.Msg()
	a := resp.Answer[0].(*dns.A)
	if !reflect.DeepEqual("100.64.0.2", a.A.String()) {
		t.Errorf("%s: a.A.String() = %v, want %v", "vpnnet view must have answered for a 100.64.0.0/24 client", a.A.String(), "100.64.0.2")
	}
}

func TestViews_ExactNameMatch(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers:  []string{"router.local. 60 IN A 192.168.1.1"},
	}}}
	v := New(cfg)

	ch := makeChain(v, "192.168.1.42:5353", "router.local.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	a := ch.Writer.Msg().Answer[0].(*dns.A)
	if !reflect.DeepEqual("192.168.1.1", a.A.String()) {
		t.Errorf("a.A.String() = %v, want %v", a.A.String(), "192.168.1.1")
	}

	// Sub-name must NOT match a non-wildcard owner.
	ch = makeChain(v, "192.168.1.42:5353", "sub.router.local.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	if ch.Writer.Written() {
		t.Errorf("%s: ch.Writer.Written() is true", "non-wildcard owner must require an exact name match")
	}
}

func TestViews_ExactOverridesWildcard(t *testing.T) {
	// RFC 4592 §3.2: an exact owner suppresses the wildcard for
	// that name. Querying "router.example.lan." must return only
	// the exact 192.168.1.1 record, not the wildcard's .3.
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers: []string{
			"*.example.lan.       60 IN A 192.168.1.3",
			"router.example.lan.  60 IN A 192.168.1.1",
		},
	}}}
	v := New(cfg)

	ch := makeChain(v, "192.168.1.42:5353", "router.example.lan.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	resp := ch.Writer.Msg()
	if len(resp.Answer) != 1 {
		t.Errorf("%s: len(resp.Answer) = %d, want %d", "exact owner must suppress the covering wildcard", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("192.168.1.1", resp.Answer[0].(*dns.A).A.String()) {
		t.Errorf("resp.Answer[0].(*dns.A).A.String() = %v, want %v", resp.Answer[0].(*dns.A).A.String(), "192.168.1.1")
	}

	// And a sibling under the wildcard still gets the wildcard answer.
	ch = makeChain(v, "192.168.1.42:5353", "other.example.lan.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	resp = ch.Writer.Msg()
	if len(resp.Answer) != 1 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("192.168.1.3", resp.Answer[0].(*dns.A).A.String()) {
		t.Errorf("resp.Answer[0].(*dns.A).A.String() = %v, want %v", resp.Answer[0].(*dns.A).A.String(), "192.168.1.3")
	}
}

func TestViews_LongestWildcardWins(t *testing.T) {
	// RFC 4592 §2.2.1 closest-encloser semantics: when multiple
	// wildcards cover the same qname, only the one rooted at the
	// longest matching suffix applies.
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"192.168.1.0/24"},
		Answers: []string{
			"*.example.lan.     60 IN A 192.168.1.3",
			"*.sub.example.lan. 60 IN A 192.168.1.4",
		},
	}}}
	v := New(cfg)

	// host.sub.example.lan. is covered by both wildcards; the
	// closer one (longer suffix) wins.
	ch := makeChain(v, "192.168.1.42:5353", "host.sub.example.lan.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	resp := ch.Writer.Msg()
	if len(resp.Answer) != 1 {
		t.Errorf("%s: len(resp.Answer) = %d, want %d", "only the longest-suffix wildcard should apply", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("192.168.1.4", resp.Answer[0].(*dns.A).A.String()) {
		t.Errorf("resp.Answer[0].(*dns.A).A.String() = %v, want %v", resp.Answer[0].(*dns.A).A.String(), "192.168.1.4")
	}

	// host.example.lan. is only covered by the outer wildcard.
	ch = makeChain(v, "192.168.1.42:5353", "host.example.lan.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	resp = ch.Writer.Msg()
	if len(resp.Answer) != 1 {
		t.Errorf("len(resp.Answer) = %d, want %d", len(resp.Answer), 1)
	}
	if !reflect.DeepEqual("192.168.1.3", resp.Answer[0].(*dns.A).A.String()) {
		t.Errorf("resp.Answer[0].(*dns.A).A.String() = %v, want %v", resp.Answer[0].(*dns.A).A.String(), "192.168.1.3")
	}
}

func TestViews_BadCIDRsAndRecordsAreSkipped(t *testing.T) {
	cfg := &config.Config{Views: []config.ViewConfig{{
		Zone:     "lannet",
		Networks: []string{"not-a-cidr", "192.168.1.0/24"},
		Answers: []string{
			"this is not a valid RR",
			"*.birb.it. 60 IN A 192.168.1.3",
		},
	}}}
	v := New(cfg)

	// Bad inputs are skipped, the surviving CIDR + record still match.
	ch := makeChain(v, "192.168.1.10:5353", "x.birb.it.", dns.TypeA)
	v.ServeDNS(context.Background(), ch)
	if !(ch.Writer.Written()) {
		t.Errorf("ch.Writer.Written() is false")
	}
}

func TestViews_WildcardBoundary(t *testing.T) {
	// "*.birb.it." must match "foo.birb.it." but NOT "birb.it." or
	// any name that just happens to end with the suffix.
	if !(nameMatches("*.birb.it.", "foo.birb.it.")) {
		t.Errorf("nameMatches('*.birb.it.', 'foo.birb.it.') is false")
	}
	if !(nameMatches("*.birb.it.", "deep.path.birb.it.")) {
		t.Errorf("nameMatches('*.birb.it.', 'deep.path.birb.it.') is false")
	}
	if nameMatches("*.birb.it.", "birb.it.") {
		t.Errorf("nameMatches('*.birb.it.', 'birb.it.') is true")
	}
	if nameMatches("*.birb.it.", "notbirb.it.") {
		t.Errorf("nameMatches('*.birb.it.', 'notbirb.it.') is true")
	}
	if !(nameMatches("router.local.", "router.local.")) {
		t.Errorf("nameMatches('router.local.', 'router.local.') is false")
	}
	if nameMatches("router.local.", "sub.router.local.") {
		t.Errorf("nameMatches('router.local.', 'sub.router.local.') is true")
	}
}

type viewDownstream struct{ calls int }

func (d *viewDownstream) Name() string                                    { return "view-test-downstream" }
func (d *viewDownstream) ServeDNS(_ context.Context, _ *middleware.Chain) { d.calls++ }

func TestViewsOwnerMode(t *testing.T) {
	records := []string{
		"*.example.lan. 60 IN A 192.0.2.1",
		"*.example.lan. 60 IN TXT \"outer\"",
		"*.sub.example.lan. 60 IN AAAA 2001:db8::1",
		"exact.example.lan. 60 IN AAAA 2001:db8::2",
		"many.example.lan. 60 IN A 192.0.2.2",
		"MANY.EXAMPLE.LAN. 60 IN A 192.0.2.3",
		"many.example.lan. 60 IN AAAA 2001:db8::3",
		"alias.example.lan. 60 IN CNAME target.example.lan.",
		"target.example.lan. 60 IN A 192.0.2.4",
		"*.alias.example.lan. 60 IN CNAME target.example.lan.",
		"chaos.only. 60 CH TXT \"chaos\"",
	}
	for _, tc := range []struct {
		name         string
		owner        string
		qtype        uint16
		wantTypes    []uint16
		fallsThrough bool
	}{
		{"RRset", "MaNy.Example.Lan.", dns.TypeA, []uint16{dns.TypeA, dns.TypeA}, false},
		{"AAAA", "many.example.lan.", dns.TypeAAAA, []uint16{dns.TypeAAAA}, false},
		{"missing MX", "many.example.lan.", dns.TypeMX, nil, false},
		{"unknown type", "many.example.lan.", 65280, nil, false},
		{"exact suppresses wildcard A", "exact.example.lan.", dns.TypeA, nil, false},
		{"exact suppresses wildcard TXT", "exact.example.lan.", dns.TypeTXT, nil, false},
		{"closer wildcard suppresses A", "host.sub.example.lan.", dns.TypeA, nil, false},
		{"closer wildcard suppresses TXT", "_acme-challenge.sub.example.lan.", dns.TypeTXT, nil, false},
		{"nested wildcard", "deep.host.sub.example.lan.", dns.TypeAAAA, []uint16{dns.TypeAAAA}, false},
		{"outer wildcard", "other.example.lan.", dns.TypeTXT, []uint16{dns.TypeTXT}, false},
		{"CNAME fallback", "alias.example.lan.", dns.TypeA, []uint16{dns.TypeCNAME}, false},
		{"CNAME question", "alias.example.lan.", dns.TypeCNAME, []uint16{dns.TypeCNAME}, false},
		{"wildcard CNAME", "deep.host.alias.example.lan.", dns.TypeTXT, []uint16{dns.TypeCNAME}, false},
		{"missing owner", "absent.other.", dns.TypeA, nil, true},
		{"apex excluded", "example.lan.", dns.TypeA, nil, true},
		{"suffix boundary", "notexample.lan.", dns.TypeA, nil, true},
		{"non-IN owner ignored", "chaos.only.", dns.TypeTXT, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, addr := range []string{"192.0.2.10:5353", "[2001:db8::10]:5353"} {
				v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24", "2001:db8::/32"}, Answers: records}}})
				d := &viewDownstream{}
				ch := middleware.NewChain([]middleware.Handler{v, d})
				req := new(dns.Msg)
				req.SetQuestion(tc.owner, tc.qtype)
				ch.Reset(mock.NewWriter("udp", addr), req)
				ch.Next(context.Background())
				if tc.fallsThrough {
					if d.calls != 1 || ch.Writer.Written() {
						t.Fatalf("%s: downstream=%d written=%v", addr, d.calls, ch.Writer.Written())
					}
					continue
				}
				if d.calls != 0 || !ch.Writer.Written() {
					t.Fatalf("%s: downstream=%d written=%v", addr, d.calls, ch.Writer.Written())
				}
				resp := ch.Writer.Msg()
				if resp.Rcode != dns.RcodeSuccess || len(resp.Ns) != 0 || len(resp.Answer) != len(tc.wantTypes) {
					t.Fatalf("unexpected response: %s", resp)
				}
				for i, typ := range tc.wantTypes {
					if resp.Answer[i].Header().Rrtype != typ || resp.Answer[i].Header().Name != tc.owner {
						t.Fatalf("unexpected answer: %s", resp.Answer[i])
					}
				}
			}
		})
	}
}

func TestViewsOwnerModeFallthroughPolicy(t *testing.T) {
	for _, tc := range []struct {
		name       string
		class, typ uint16
		addr       string
	}{
		{"CHAOS", dns.ClassCHAOS, dns.TypeA, "192.0.2.10:53"},
		{"NONE", dns.ClassNONE, dns.TypeA, "192.0.2.10:53"},
		{"ANY class", dns.ClassANY, dns.TypeA, "192.0.2.10:53"},
		{"ANY", dns.ClassINET, dns.TypeANY, "192.0.2.10:53"},
		{"AXFR", dns.ClassINET, dns.TypeAXFR, "192.0.2.10:53"},
		{"IXFR", dns.ClassINET, dns.TypeIXFR, "192.0.2.10:53"},
		{"NXNAME", dns.ClassINET, dns.TypeNXNAME, "192.0.2.10:53"},
		{"internal", dns.ClassINET, dns.TypeAAAA, "127.0.0.255:0"},
		{"outside", dns.ClassINET, dns.TypeAAAA, "198.51.100.10:53"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24", "127.0.0.0/8"}, Answers: []string{"name.local. 60 IN A 192.0.2.1"}}}})
			d := &viewDownstream{}
			ch := middleware.NewChain([]middleware.Handler{v, d})
			req := new(dns.Msg)
			req.SetQuestion("name.local.", tc.typ)
			req.Question[0].Qclass = tc.class
			ch.Reset(mock.NewWriter("udp", tc.addr), req)
			ch.Next(context.Background())
			if d.calls != 1 || ch.Writer.Written() {
				t.Fatalf("downstream=%d written=%v", d.calls, ch.Writer.Written())
			}
		})
	}
}

func TestViewsFirstClientMatchAndOverlayCompatibility(t *testing.T) {
	for _, mode := range []string{"", "overlay", "authoritative-owner"} {
		for _, tc := range []struct {
			name  string
			typ   uint16
			want  uint16
			falls bool
		}{
			{"exact missing type", dns.TypeA, dns.TypeA, false},
			{"missing type", dns.TypeMX, 0, true},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				v := New(&config.Config{Views: []config.ViewConfig{
					{Mode: mode, Networks: []string{"192.0.2.0/24"}, Answers: []string{"*.local. 60 IN A 192.0.2.1", "name.local. 60 IN AAAA 2001:db8::1"}},
					{Mode: "authoritative-owner", Networks: []string{"192.0.2.10/32"}, Answers: []string{"name.local. 60 IN MX 10 mail.local."}},
				}})
				d := &viewDownstream{}
				ch := middleware.NewChain([]middleware.Handler{v, d})
				req := new(dns.Msg)
				req.SetQuestion("name.local.", tc.typ)
				ch.Reset(mock.NewWriter("udp", "192.0.2.10:53"), req)
				ch.Next(context.Background())
				switch {
				case mode == "authoritative-owner":
					if d.calls != 0 || !ch.Writer.Written() || len(ch.Writer.Msg().Answer) != 0 {
						t.Fatal("first owner view must answer NODATA")
					}
				case tc.falls:
					if d.calls != 1 || ch.Writer.Written() {
						t.Fatal("overlay must fall through without consulting later view")
					}
				case !ch.Writer.Written() || len(ch.Writer.Msg().Answer) != 1 || ch.Writer.Msg().Answer[0].Header().Rrtype != tc.want:
					t.Fatal("overlay must retain type-first wildcard match")
				}
			})
		}
	}
}

func TestViewsOwnerModeReplyFlags(t *testing.T) {
	for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, rd := range []bool{false, true} {
			for _, cd := range []bool{false, true} {
				v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: []string{"name.local. 60 IN A 192.0.2.1"}}}})
				ch := makeChain(v, "192.0.2.10:53", "name.local.", typ)
				ch.Request.Msg().RecursionDesired = rd
				ch.Request.Msg().CheckingDisabled = cd
				ch.Request.Msg().AuthenticatedData = true
				v.ServeDNS(context.Background(), ch)
				resp := ch.Writer.Msg()
				if resp == nil || !resp.Authoritative || !resp.RecursionAvailable || resp.AuthenticatedData || resp.RecursionDesired != rd || resp.CheckingDisabled != cd {
					t.Fatalf("unexpected flags: %v", resp)
				}
			}
		}
	}
}

func TestViewsOwnerModeFirstViewMissingOwner(t *testing.T) {
	v := New(&config.Config{Views: []config.ViewConfig{
		{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: []string{"other.local. 60 IN A 192.0.2.1"}},
		{Mode: "authoritative-owner", Networks: []string{"192.0.2.10/32"}, Answers: []string{"name.local. 60 IN A 192.0.2.2"}},
	}})
	d := &viewDownstream{}
	ch := middleware.NewChain([]middleware.Handler{v, d})
	req := new(dns.Msg)
	req.SetQuestion("name.local.", dns.TypeA)
	ch.Reset(mock.NewWriter("udp", "192.0.2.10:53"), req)
	ch.Next(context.Background())
	if d.calls != 1 || ch.Writer.Written() {
		t.Fatal("missing owner in first client view must fall through")
	}
}

func TestViewsOwnerModeRequestedTypeBeforeCNAMEAndClass(t *testing.T) {
	v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: []string{
		"name.local. 60 CH TXT \"ignored\"",
		"name.local. 60 IN TXT \"local\"",
		"name.local. 60 IN CNAME target.local.",
		"name.local. 60 IN TYPE65280 \\# 1 ff",
	}}}})
	for _, typ := range []uint16{dns.TypeTXT, 65280} {
		ch := makeChain(v, "192.0.2.10:53", "name.local.", typ)
		v.ServeDNS(context.Background(), ch)
		resp := ch.Writer.Msg()
		if resp == nil || len(resp.Answer) != 1 || resp.Answer[0].Header().Rrtype != typ || resp.Answer[0].Header().Class != dns.ClassINET {
			t.Fatalf("unexpected RRset: %v", resp)
		}
	}
}

func TestViewsOwnerModeSelectionIgnoresRecordOrder(t *testing.T) {
	for _, tc := range []struct {
		name, qname string
		records     []string
	}{
		{"exact missing type", "exact.example.lan.", []string{
			"*.example.lan. 60 IN A 192.0.2.1",
			"exact.example.lan. 60 IN AAAA 2001:db8::1",
		}},
		{"closer wildcard missing type", "host.sub.example.lan.", []string{
			"*.example.lan. 60 IN A 192.0.2.1",
			"*.sub.example.lan. 60 IN AAAA 2001:db8::1",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, reverse := range []bool{false, true} {
				records := append([]string(nil), tc.records...)
				if reverse {
					for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
						records[i], records[j] = records[j], records[i]
					}
				}
				v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: records}}})
				d := &viewDownstream{}
				ch := middleware.NewChain([]middleware.Handler{v, d})
				req := new(dns.Msg)
				req.SetQuestion(tc.qname, dns.TypeA)
				ch.Reset(mock.NewWriter("udp", "192.0.2.10:53"), req)
				ch.Next(context.Background())
				resp := ch.Writer.Msg()
				if d.calls != 0 || resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 0 || len(resp.Ns) != 0 {
					t.Fatalf("reverse=%v: downstream=%d response=%v, want local NODATA", reverse, d.calls, resp)
				}
			}
		})
	}
}

func TestViewsOwnerModeRootOwnerAndWildcardBoundary(t *testing.T) {
	records := []string{
		". 60 IN A 192.0.2.1",
		"*. 60 IN AAAA 2001:db8::1",
	}
	for _, reverse := range []bool{false, true} {
		answers := append([]string(nil), records...)
		orderName := "original"
		if reverse {
			answers[0], answers[1] = answers[1], answers[0]
			orderName = "reversed"
		}
		v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: answers}}})
		for _, tc := range []struct {
			name        string
			qname       string
			qtype       uint16
			wantData    string
			wantAnswers int
		}{
			{"root A exact owner", ".", dns.TypeA, "192.0.2.1", 1},
			{"root AAAA exact owner NODATA", ".", dns.TypeAAAA, "", 0},
			{"nonroot AAAA root wildcard", "example.", dns.TypeAAAA, "2001:db8::1", 1},
		} {
			t.Run(orderName+"/"+tc.name, func(t *testing.T) {
				d := &viewDownstream{}
				ch := middleware.NewChain([]middleware.Handler{v, d})
				req := new(dns.Msg)
				req.SetQuestion(tc.qname, tc.qtype)
				ch.Reset(mock.NewWriter("udp", "192.0.2.10:5353"), req)
				ch.Next(context.Background())
				resp := ch.Writer.Msg()
				if d.calls != 0 || resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Ns) != 0 || len(resp.Answer) != tc.wantAnswers {
					t.Fatalf("downstream=%d response=%v, want local answer count %d", d.calls, resp, tc.wantAnswers)
				}
				if len(resp.Question) != 1 || resp.Question[0].Name != tc.qname {
					t.Fatalf("response question = %v, want owner %q", resp.Question, tc.qname)
				}
				if tc.wantAnswers != 0 {
					if got := resp.Answer[0].Header(); got.Name != tc.qname || got.Rrtype != tc.qtype || got.Class != dns.ClassINET {
						t.Fatalf("answer header = %+v, want %s IN type %d", got, tc.qname, tc.qtype)
					}
					if got := ownerTestRData(resp.Answer[0]); got != tc.wantData {
						t.Fatalf("answer data = %q, want %q", got, tc.wantData)
					}
				}
			})
		}
	}
}

func TestViewsOwnerModeResponseIsolation(t *testing.T) {
	v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: []string{"*.example.lan. 60 IN A 192.0.2.1"}}}})
	query := func(qname string) *dns.A {
		t.Helper()
		ch := makeChain(v, "192.0.2.10:53", qname, dns.TypeA)
		v.ServeDNS(context.Background(), ch)
		resp := ch.Writer.Msg()
		if resp == nil || len(resp.Answer) != 1 {
			t.Fatalf("%s: unexpected response: %v", qname, resp)
		}
		a, ok := resp.Answer[0].(*dns.A)
		if !ok || a.Hdr.Name != qname || a.A.String() != "192.0.2.1" {
			t.Fatalf("%s: unexpected answer: %v", qname, resp.Answer[0])
		}
		return a
	}
	first := query("First.example.lan.")
	first.Hdr.Name = "mutated.invalid."
	for i := range first.A {
		first.A[i] = 0
	}
	second := query("second.example.lan.")
	second.Hdr.Name = "another.invalid."
	for i := range second.A {
		second.A[i] = 255
	}
	query("First.example.lan.")
}

func TestViewsOwnerModeEscapedIdentity(t *testing.T) {
	for _, tc := range []struct {
		name         string
		answers      []string
		qname        string
		qtype        uint16
		wantTypes    []uint16
		wantData     []string
		fallsThrough bool
	}{
		{
			name:      "sole decimal owner present A",
			answers:   []string{`\097lias.example. 60 IN A 192.0.2.1`},
			qname:     "alias.example.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA},
			wantData:  []string{"192.0.2.1"},
		},
		{
			name:      "decimal owner and missing type",
			answers:   []string{`\097lias.example. 60 IN A 192.0.2.1`},
			qname:     "alias.example.",
			qtype:     dns.TypeAAAA,
			wantTypes: nil,
		},
		{
			name: "mixed escaped plain case RRset preserves query spelling",
			answers: []string{
				`alias.example. 60 IN A 192.0.2.1`,
				`\097lias.example. 60 IN A 192.0.2.2`,
				`ALIAS.EXAMPLE. 60 IN A 192.0.2.3`,
			},
			qname:     "AlIaS.Example.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA, dns.TypeA, dns.TypeA},
			wantData:  []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"},
		},
		{
			name: "escaped exact owner suppresses covering wildcard",
			answers: []string{
				`*.example. 60 IN A 192.0.2.1`,
				`\097lias.example. 60 IN AAAA 2001:db8::1`,
			},
			qname:     "alias.example.",
			qtype:     dns.TypeA,
			wantTypes: nil,
		},
		{
			name:      "escaped CNAME owner fallback",
			answers:   []string{`\097lias.example. 60 IN CNAME target.example.`},
			qname:     "alias.example.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeCNAME},
			wantData:  []string{"target.example."},
		},
		{
			// An escaped dot belongs to its label, so this owner is outside
			// *.example.lan even though its presentation text contains that suffix.
			name:         "escaped dot is not a wildcard label boundary",
			answers:      []string{`*.example.lan. 60 IN A 192.0.2.1`},
			qname:        `foo\.example.lan.`,
			qtype:        dns.TypeA,
			fallsThrough: true,
		},
		{
			name:         "escaped dot is not a wildcard label boundary AAAA",
			answers:      []string{`*.example.lan. 60 IN AAAA 2001:db8::1`},
			qname:        `foo\.example.lan.`,
			qtype:        dns.TypeAAAA,
			fallsThrough: true,
		},
		{
			name:         "escaped dot misses absent AAAA too",
			answers:      []string{`*.example.lan. 60 IN A 192.0.2.1`},
			qname:        `foo\.example.lan.`,
			qtype:        dns.TypeAAAA,
			fallsThrough: true,
		},
		{
			// Two backslashes leave the following dot as a label separator.
			name:      "even backslash parity leaves label boundary",
			answers:   []string{`*.example.lan. 60 IN A 192.0.2.1`},
			qname:     `foo\\.example.lan.`,
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA},
			wantData:  []string{"192.0.2.1"},
		},
		{
			// Three backslashes escape the dot after the escaped backslash.
			name:         "odd backslash parity escapes label boundary",
			answers:      []string{`*.example.lan. 60 IN A 192.0.2.1`},
			qname:        `foo\\\.example.lan.`,
			qtype:        dns.TypeA,
			fallsThrough: true,
		},
		{
			name: "equivalent escaped wildcard labels group and nest",
			answers: []string{
				`\042.example.lan. 60 IN A 192.0.2.1`,
				`\*.example.lan. 60 IN AAAA 2001:db8::1`,
				`\*.sub.example.lan. 60 IN TXT "nested"`,
			},
			qname:     "deep.host.sub.example.lan.",
			qtype:     dns.TypeTXT,
			wantTypes: []uint16{dns.TypeTXT},
			wantData:  []string{"nested"},
		},
		{
			name: "escaped suffix spelling groups wildcard owner",
			answers: []string{
				`*.example.lan. 60 IN A 192.0.2.1`,
				`*.ex\097mple.lan. 60 IN AAAA 2001:db8::1`,
			},
			qname:     "host.example.lan.",
			qtype:     dns.TypeAAAA,
			wantTypes: []uint16{dns.TypeAAAA},
			wantData:  []string{"2001:db8::1"},
		},
		{
			name: "escaped wildcard spellings share one RRset",
			answers: []string{
				`\042.example.lan. 60 IN A 192.0.2.1`,
				`\*.example.lan. 60 IN A 192.0.2.2`,
			},
			qname:     "host.example.lan.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA, dns.TypeA},
			wantData:  []string{"192.0.2.1", "192.0.2.2"},
		},
		{
			name:         "wildcard excludes apex",
			answers:      []string{`\*.example.lan. 60 IN A 192.0.2.1`},
			qname:        "example.lan.",
			qtype:        dns.TypeA,
			fallsThrough: true,
		},
		{
			name:      "root wildcard matches nonroot",
			answers:   []string{`\042. 60 IN A 192.0.2.1`},
			qname:     "example.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA},
			wantData:  []string{"192.0.2.1"},
		},
		{
			name:         "root wildcard excludes root",
			answers:      []string{`\042. 60 IN A 192.0.2.1`},
			qname:        ".",
			qtype:        dns.TypeA,
			fallsThrough: true,
		},
		{
			name:      "literal root wildcard matches nonroot",
			answers:   []string{`*. 60 IN A 192.0.2.1`},
			qname:     "example.",
			qtype:     dns.TypeA,
			wantTypes: []uint16{dns.TypeA},
			wantData:  []string{"192.0.2.1"},
		},
		{
			name:         "literal root wildcard excludes root",
			answers:      []string{`*. 60 IN A 192.0.2.1`},
			qname:        ".",
			qtype:        dns.TypeA,
			fallsThrough: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: tc.answers}}})
			d := &viewDownstream{}
			ch := middleware.NewChain([]middleware.Handler{v, d})
			req := new(dns.Msg)
			req.SetQuestion(tc.qname, tc.qtype)
			ch.Reset(mock.NewWriter("udp", "192.0.2.10:5353"), req)
			ch.Next(context.Background())
			if tc.fallsThrough {
				if d.calls != 1 || ch.Writer.Written() {
					t.Fatalf("downstream=%d written=%v, want fallthrough without response", d.calls, ch.Writer.Written())
				}
				return
			}
			if d.calls != 0 || !ch.Writer.Written() {
				t.Fatalf("downstream=%d written=%v, want local response", d.calls, ch.Writer.Written())
			}
			resp := ch.Writer.Msg()
			if resp.Rcode != dns.RcodeSuccess || len(resp.Ns) != 0 || len(resp.Answer) != len(tc.wantTypes) {
				t.Fatalf("unexpected response: %s", resp)
			}
			for i, typ := range tc.wantTypes {
				if got := resp.Answer[i].Header(); got.Rrtype != typ || got.Name != tc.qname {
					t.Fatalf("answer %d header = %+v, want type %d owner %q", i, got, typ, tc.qname)
				}
				if data := ownerTestRData(resp.Answer[i]); data != tc.wantData[i] {
					t.Fatalf("answer %d data = %q, want %q", i, data, tc.wantData[i])
				}
			}
		})
	}
}

func TestViewsOwnerModeEscapedWildcardSpecificity(t *testing.T) {
	// The escaped broad suffix has a longer spelling in bytes despite having
	// fewer labels than the closer plain suffix. Selection is independent of
	// qtype and record order.
	records := []string{
		`*.\101\120\097\109\112\108\101.lan. 60 IN A 192.0.2.1`,
		`*.sub.example.lan. 60 IN AAAA 2001:db8::1`,
	}
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		for _, order := range []struct {
			name    string
			reverse bool
		}{{"original", false}, {"reversed", true}} {
			t.Run(dns.TypeToString[qtype]+"/"+order.name, func(t *testing.T) {
				answers := append([]string(nil), records...)
				if order.reverse {
					answers[0], answers[1] = answers[1], answers[0]
				}
				v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Networks: []string{"192.0.2.0/24"}, Answers: answers}}})
				d := &viewDownstream{}
				ch := middleware.NewChain([]middleware.Handler{v, d})
				req := new(dns.Msg)
				req.SetQuestion("host.sub.example.lan.", qtype)
				ch.Reset(mock.NewWriter("udp", "192.0.2.10:5353"), req)
				ch.Next(context.Background())
				resp := ch.Writer.Msg()
				if d.calls != 0 || resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Ns) != 0 {
					t.Fatalf("reverse=%v: downstream=%d response=%v, want local successful answer", order.reverse, d.calls, resp)
				}
				if qtype == dns.TypeA {
					if len(resp.Answer) != 0 {
						t.Fatalf("reverse=%v: answers=%v, want NODATA from closer wildcard owner", order.reverse, resp.Answer)
					}
				} else if len(resp.Answer) != 1 || ownerTestRData(resp.Answer[0]) != "2001:db8::1" || resp.Answer[0].Header().Name != "host.sub.example.lan." {
					t.Fatalf("reverse=%v: answers=%v, want configured closer wildcard AAAA", order.reverse, resp.Answer)
				}
			})
		}
	}
}

func ownerTestRData(rr dns.RR) string {
	switch r := rr.(type) {
	case *dns.A:
		return r.A.String()
	case *dns.AAAA:
		return r.AAAA.String()
	case *dns.CNAME:
		return r.Target
	case *dns.TXT:
		if len(r.Txt) != 0 {
			return r.Txt[0]
		}
	}
	return ""
}

func TestViewsOwnerModeMatchingAlloc(t *testing.T) {
	for _, tc := range []struct {
		name, owner, qname string
	}{
		{"exact owner NODATA", `\097lias.example.`, "alias.example."},
		{"wildcard owner NODATA", `\*.example.lan.`, "host.example.lan."},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := New(&config.Config{Views: []config.ViewConfig{{Mode: "authoritative-owner", Answers: []string{tc.owner + ` 60 IN A 192.0.2.1`}}}})
			cv := v.views[0]
			q := dns.Question{Name: tc.qname, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
			answers, found := cv.ownerAnswers(q)
			if !found || len(answers) != 0 {
				t.Fatal("ownerAnswers did not select NODATA owner")
			}
			var got []dns.RR
			var gotFound bool
			allocs := testing.AllocsPerRun(100, func() { got, gotFound = cv.ownerAnswers(q) })
			if allocs != 0 {
				t.Fatalf("matching owner allocated %g times per run, want 0", allocs)
			}
			if !gotFound || len(got) != 0 {
				t.Fatalf("ownerAnswers = (%v, %v), want selected NODATA owner", got, gotFound)
			}
		})
	}
}
