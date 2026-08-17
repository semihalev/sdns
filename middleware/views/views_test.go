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
