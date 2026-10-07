package hostsfile

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

func policyHostsfile(t *testing.T, content string, checks bool, zones []string) *Hostsfile {
	t.Helper()
	h := New(&config.Config{HostsFile: createTempHostsFile(t, content), HostsFileCheckNames: checks, HostsFileZones: zones})
	if h == nil {
		t.Fatal("hostsfile failed to load")
	}
	if h.watcher != nil {
		if err := h.watcher.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func TestValidHostname(t *testing.T) {
	label := strings.Repeat("a", 63)
	max := label + "." + label + "." + label + "." + strings.Repeat("b", 61)
	wildcardMax := "*." + label + "." + label + "." + label + "." + strings.Repeat("b", 59)
	for _, name := range []string{"localhost", "A0.b-2", "xn--caf-dma.example.", "*.Example.COM.", label, max, max + ".", wildcardMax} {
		if !validHostname(name) {
			t.Errorf("valid hostname rejected: %q", name)
		}
	}
	for _, name := range []string{"", ".", "..", "a..b", ".a", "a..", "-a", "a-", "a.-b", "a_b", "café.example", `a\046b.example`, "*", "*.", "a*.example", "**.example", "*.*.example", strings.Repeat("a", 64), max + "b", wildcardMax + "b"} {
		if validHostname(name) {
			t.Errorf("invalid hostname accepted: %q", name)
		}
	}
}

func TestHostsfilePolicyCombinations(t *testing.T) {
	content := "192.0.2.1 good.example outside.test bad_name.example\n"
	for _, checks := range []bool{false, true} {
		for _, restricted := range []bool{false, true} {
			t.Run(fmt.Sprintf("checks=%v/zones=%v", checks, restricted), func(t *testing.T) {
				var zones []string
				if restricted {
					zones = []string{"EXAMPLE."}
				}
				h := policyHostsfile(t, content, checks, zones)
				for _, tc := range []struct {
					name string
					want bool
				}{{"good.example", true}, {"outside.test", !restricted}, {"bad_name.example", !checks}} {
					if got := h.hostExists(h.getDB(), tc.name); got != tc.want {
						t.Errorf("%s exists=%v want %v", tc.name, got, tc.want)
					}
				}
			})
		}
	}
}

func TestHostsfilePolicyZonesAndNormalization(t *testing.T) {
	content := "192.0.2.1 OUTSIDE.test Apex.Example. Alias.Example. example badexample x.badexample X.Other.\n" +
		"192.0.2.2 *.WILD.Example.\n" +
		"192.0.2.3 outside.test *.outside.test normal.example\n" +
		"192.0.2.4 invalid*.example good.example *.Last.Example. ignored.example\n"
	h := policyHostsfile(t, content, true, []string{"ExAmPlE.", "other"})
	db := h.getDB()
	for _, name := range []string{"apex.example", "alias.example", "example", "x.other", "x.wild.example", "wild.example", "normal.example", "x.last.example"} {
		if !h.hostExists(db, name) {
			t.Errorf("missing accepted %s", name)
		}
	}
	for _, name := range []string{"outside.test", "badexample", "x.badexample", "good.example", "ignored.example"} {
		if h.hostExists(db, name) {
			t.Errorf("unexpected accepted %s", name)
		}
	}
	rrs, ok := h.lookupCNAME(db, "ALIAS.EXAMPLE.")
	if !ok || rrs[0].(*dns.CNAME).Target != "apex.example." {
		t.Fatalf("promoted alias CNAME=%v found=%v", rrs, ok)
	}
	if got := db.reverse["192.0.2.1"]; !reflect.DeepEqual(got, []string{"apex.example"}) {
		t.Fatalf("reverse=%v", got)
	}
	if len(db.wildcards) != 2 || db.wildcards[1].Pattern != "*.last.example" {
		t.Fatalf("wildcards=%v", db.wildcards)
	}
	root := policyHostsfile(t, "192.0.2.1 single outside.test\n", false, []string{"."})
	if len(root.getDB().hosts) != 2 {
		t.Fatal("root zone must include every name")
	}
}

func TestHostsfilePolicyDisabledPreservesSpellings(t *testing.T) {
	h := policyHostsfile(t, "192.0.2.1 Dotted.Example. bad_name\n192.0.2.2 *.UPPER.Example\n192.0.2.3 a*.example normal.example\n", false, nil)
	db := h.getDB()
	if db.hosts["dotted.example."] == nil || db.hosts["bad_name"] == nil {
		t.Fatal("legacy exact storage changed")
	}
	if h.hostExists(db, "dotted.example.") || h.hostExists(db, "x.upper.example") || h.hostExists(db, "normal.example") {
		t.Fatal("legacy lookup or wildcard selection changed")
	}
	if len(db.wildcards) != 2 || db.wildcards[0].Pattern != "*.UPPER.Example" || db.wildcards[1].Pattern != "a*.example" {
		t.Fatal("legacy wildcard spelling changed")
	}
}

func TestHostsfilePolicyPromotionAggregationAndPTR(t *testing.T) {
	content := "192.0.2.1 bad_name accepted.example ACCEPTED.EXAMPLE accepted.example alias.example alias.example\n" +
		"2001:db8::1 outside.test ACCEPTED.EXAMPLE. alias.example\n" +
		"192.0.2.2 first.example promoted.example\n" +
		"2001:db8::2 bad_name promoted.example last.example\n" +
		"192.0.2.3 repeat.example repeat.example repeat.example\n" +
		"192.0.2.4 bad_name *.Last.Example. *.last.example outside.test\n"
	h := policyHostsfile(t, content, true, []string{"example"})
	db := h.getDB()
	for _, name := range []string{"accepted.example", "alias.example", "promoted.example"} {
		a, af := h.lookupA(db, name)
		aaaa, vf := h.lookupAAAA(db, name)
		if !af || !vf || len(a) != 1 || len(aaaa) != 1 {
			t.Errorf("%s A=%v AAAA=%v", name, a, aaaa)
		}
	}
	for _, tc := range []struct{ name, target string }{{"alias.example", "accepted.example."}, {"promoted.example", "first.example."}, {"last.example", "promoted.example."}} {
		rrs, ok := h.lookupCNAME(db, tc.name)
		if !ok || rrs[0].(*dns.CNAME).Target != tc.target {
			t.Errorf("%s CNAME=%v want %s", tc.name, rrs, tc.target)
		}
	}
	if got := len(db.hosts["repeat.example"].IPv4); got != 1 {
		t.Errorf("repeated names addresses=%d want1", got)
	}
	if _, ok := h.lookupCNAME(db, "repeat.example"); ok {
		t.Fatal("a primary name repeated as an alias must not create a self-CNAME")
	}
	for _, tc := range []struct{ ip, target string }{{"192.0.2.1", "accepted.example."}, {"2001:db8::1", "accepted.example."}, {"2001:db8::2", "promoted.example."}} {
		rrs, ok := h.lookupPTR(db, reverseName(tc.ip))
		if !ok || len(rrs) != 1 || rrs[0].(*dns.PTR).Ptr != tc.target {
			t.Errorf("%s PTR=%v want %s", tc.ip, rrs, tc.target)
		}
	}
	if len(db.ptrs["192.0.2.4"]) != 0 || db.hosts["bad_name"] != nil || db.hosts["outside.test"] != nil {
		t.Fatal("rejected names entered database")
	}
}

func TestHostsfilePolicyDeduplicatesAcceptedNamesPerRow(t *testing.T) {
	content := "192.0.2.10 Primary.Example. primary.example PRIMARY.EXAMPLE alias.example ALIAS.EXAMPLE. alias.example\n"
	for _, checks := range []bool{false, true} {
		for _, restricted := range []bool{false, true} {
			if !checks && !restricted {
				// With both controls off, the historical spelling and duplicate
				// behavior is pinned separately below.
				continue
			}
			t.Run(fmt.Sprintf("checks=%v/zones=%v", checks, restricted), func(t *testing.T) {
				var zones []string
				if restricted {
					zones = []string{"example"}
				}
				h := policyHostsfile(t, content, checks, zones)
				entry := h.getDB().hosts["primary.example"]
				if entry == nil || len(entry.IPv4) != 1 || len(entry.aRRs) != 1 {
					t.Fatalf("primary entry=%+v", entry)
				}
				if got := len(entry.Aliases); got != 1 || entry.Aliases[0] != "alias.example" {
					t.Fatalf("aliases=%v want one canonical alias", entry.Aliases)
				}
				if _, ok := h.lookupCNAME(h.getDB(), "primary.example"); ok {
					t.Fatal("primary name produced a self-CNAME")
				}
				cnames, ok := h.lookupCNAME(h.getDB(), "alias.example")
				if !ok || len(cnames) != 1 || cnames[0].(*dns.CNAME).Target != "primary.example." {
					t.Fatalf("alias CNAME=%v found=%v", cnames, ok)
				}
			})
		}
	}

	// The zone matcher uses DNS wire identity too: these two spellings name
	// the same escaped-dot label. Strict hostname checks reject both tokens.
	h := policyHostsfile(t, "192.0.2.11 corp\\.example corp\\046example child.corp\\.example child.corp\\046example\n", false, []string{`corp\.example`})
	if got := len(h.getDB().hosts); got != 2 {
		t.Fatalf("escaped equivalent zone names hosts=%v", h.getDB().hosts)
	}
	entry := h.getDB().hosts[`corp\.example`]
	if entry == nil || len(entry.IPv4) != 1 {
		t.Fatalf("escaped apex entry=%+v", entry)
	}
	if cnames, ok := h.lookupCNAME(h.getDB(), `child.corp\.example`); !ok || len(cnames) != 1 || cnames[0].(*dns.CNAME).Target != `corp\.example.` {
		t.Fatalf("escaped child CNAME=%v found=%v", cnames, ok)
	}
	strict := policyHostsfile(t, "192.0.2.11 corp\\.example corp\\046example\n", true, []string{`corp\.example`})
	if len(strict.getDB().hosts) != 0 {
		t.Fatalf("strict hostname checks accepted escaped raw tokens: %v", strict.getDB().hosts)
	}
}

func TestHostsfilePolicyDuplicateLegacyBehavior(t *testing.T) {
	legacy := policyHostsfile(t, "192.0.2.20 repeat.example repeat.example repeat.example\n", false, nil)
	if got := len(legacy.getDB().hosts["repeat.example"].IPv4); got != 3 {
		t.Fatalf("disabled policy addresses=%d want3", got)
	}
	if cnames, ok := legacy.lookupCNAME(legacy.getDB(), "repeat.example"); !ok || len(cnames) != 1 || cnames[0].(*dns.CNAME).Target != "repeat.example." {
		t.Fatalf("disabled policy self-CNAME=%v found=%v", cnames, ok)
	}

	// The disabled importer keeps dotted and undotted spellings separate.
	// Normal queries still find one address and no CNAME for the primary.
	dottedLegacy := policyHostsfile(t, "192.0.2.21 dotted.example dotted.example.\n", false, nil)
	if rrs, ok := dottedLegacy.lookupA(dottedLegacy.getDB(), "dotted.example."); !ok || len(rrs) != 1 {
		t.Fatalf("disabled dotted/undotted A=%v found=%v", rrs, ok)
	}
	if _, ok := dottedLegacy.lookupCNAME(dottedLegacy.getDB(), "dotted.example."); ok {
		t.Fatal("disabled dotted/undotted primary acquired a CNAME")
	}

	dotted := policyHostsfile(t, "192.0.2.22 dotted.example. dotted.example.\n", true, nil)
	if got := len(dotted.getDB().hosts["dotted.example"].IPv4); got != 1 {
		t.Fatalf("enabled dotted duplicate addresses=%d want1", got)
	}
	if _, ok := dotted.lookupCNAME(dotted.getDB(), "dotted.example."); ok {
		t.Fatal("enabled dotted duplicate produced a self-CNAME")
	}
}

func TestHostsfilePolicyReloadAndConfigCopy(t *testing.T) {
	zones := []string{"example"}
	h := policyHostsfile(t, "192.0.2.1 old.example alias.example alias.example\n192.0.2.2 *.wild.example *.wild.example\n", true, zones)
	zones[0] = "outside.test"
	if err := os.WriteFile(h.path, []byte("192.0.2.1 bad_name outside.test\n192.0.2.3 new.example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := h.load(); err != nil {
		t.Fatal(err)
	}
	db := h.getDB()
	for _, name := range []string{"old.example", "alias.example", "x.wild.example", "outside.test", "bad_name"} {
		if h.hostExists(db, name) {
			t.Errorf("reload retained/reintroduced %s", name)
		}
	}
	if !h.hostExists(db, "new.example") || len(db.wildcards) != 0 || len(db.ptrs["192.0.2.1"]) != 0 || len(db.ptrs["192.0.2.2"]) != 0 {
		t.Fatal("reload/copy policy failed")
	}
}

func TestHostsfilePolicyWireAndDecoded(t *testing.T) {
	h := policyHostsfile(t, "192.0.2.1 outside.test Accepted.Example. Alias.Example.\n2001:db8::1 bad_name V6.Example.\n192.0.2.2 *.Wild.Example.\n", true, []string{"example"})
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
	}{
		{"Accepted.Example.", dns.TypeA, "192.0.2.1"}, {"alias.example.", dns.TypeCNAME, "accepted.example."}, {"v6.example.", dns.TypeAAAA, "2001:db8::1"}, {"1.2.0.192.in-addr.arpa.", dns.TypePTR, "accepted.example."}, {"x.wild.example.", dns.TypeA, "192.0.2.2"}, {"accepted.example.", dns.TypeAAAA, "NODATA"}, {"outside.test.", dns.TypeA, "upstream"}, {"bad_name.", dns.TypeA, "upstream"},
	} {
		for _, wire := range []bool{false, true} {
			passed := false
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				passed = true
				if wire && !ch.Request.Undecoded() {
					t.Error("miss decoded request")
				}
				ch.Cancel()
			})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{h, next})
			if wire {
				ch.ResetWire(w, wireHostsRequest(t, tc.name, tc.qtype))
			} else {
				q := new(dns.Msg)
				q.SetQuestion(tc.name, tc.qtype)
				ch.Reset(w, q)
			}
			ch.Next(context.Background())
			got := "upstream"
			if !passed {
				if !w.Written() || w.Rcode() != dns.RcodeSuccess {
					t.Fatalf("%s wire=%v no successful reply", tc.name, wire)
				}
				if wire && !ch.Request.Undecoded() {
					t.Error("hit decoded request")
				}
				ans := w.Msg().Answer
				if len(ans) == 0 {
					got = "NODATA"
				} else if len(ans) == 1 {
					switch rr := ans[0].(type) {
					case *dns.A:
						got = rr.A.String()
					case *dns.AAAA:
						got = rr.AAAA.String()
					case *dns.CNAME:
						got = rr.Target
					case *dns.PTR:
						got = rr.Ptr
					}
					if _, err := w.Msg().Pack(); err != nil {
						t.Fatalf("pack response: %v", err)
					}
				}
			}
			if got != tc.want {
				t.Errorf("%s type=%d wire=%v got %s want %s", tc.name, tc.qtype, wire, got, tc.want)
			}
		}
	}
}

func TestHostsfileCheckNamesFiltersEveryToken(t *testing.T) {
	h := policyHostsfile(t, "192.0.2.1 invalid*.example -bad Good.Example. bad_name Alias.Example. a..b\n192.0.2.2 * **.example café.example\n", true, nil)
	db := h.getDB()
	if len(db.hosts) != 2 || len(db.wildcards) != 0 {
		t.Fatalf("hosts=%v wildcards=%v", db.hosts, db.wildcards)
	}
	rrs, ok := h.lookupCNAME(db, "alias.example")
	if !ok || rrs[0].(*dns.CNAME).Target != "good.example." {
		t.Fatalf("alias=%v found=%v", rrs, ok)
	}
	if len(db.ptrs["192.0.2.2"]) != 0 {
		t.Fatal("empty surviving row created PTR")
	}
}

func TestHostsfileZoneDNSIdentity(t *testing.T) {
	for _, tc := range []struct {
		zone, content string
		count         int
	}{
		{"k.example", "192.0.2.1 K.example\n192.0.2.2 K.EXAMPLE\n", 1},
		{"K.example", "192.0.2.1 K.example\n192.0.2.2 K.EXAMPLE\n", 1},
		{`corp\.example`, "192.0.2.1 corp\\.example\n192.0.2.2 child.corp\\046example.\n192.0.2.3 corp.example\n", 2},
		{`corp\.example.`, "192.0.2.1 corp\\046example.\n192.0.2.2 child.corp\\.example\n192.0.2.3 corp.example\n", 2},
		{`corp\.`, "192.0.2.1 corp\\.\n192.0.2.2 child.corp\\046.\n192.0.2.3 corp\n", 2},
		{`corp\..`, "192.0.2.1 corp\\046.\n192.0.2.2 child.corp\\.\n192.0.2.3 corp\n", 2},
	} {
		t.Run(tc.zone, func(t *testing.T) {
			h := policyHostsfile(t, tc.content, false, []string{tc.zone})
			if got := len(h.getDB().hosts); got != tc.count {
				t.Fatalf("hosts=%v count=%d want%d", h.getDB().hosts, got, tc.count)
			}
			for name, entry := range h.getDB().hosts {
				if name == "k.example" && entry.IPv4[0].String() != "192.0.2.2" {
					t.Fatal("Unicode name folded into ASCII zone")
				}
				msg := new(dns.Msg)
				msg.Answer = entry.aRRs
				if _, err := msg.Pack(); err != nil {
					t.Errorf("%q response pack: %v", name, err)
				}
			}
		})
	}
}

func TestHostsfileScopedWildcardLabelBoundaries(t *testing.T) {
	for _, scoped := range []bool{false, true} {
		var zones []string
		if scoped {
			zones = []string{"corp.example"}
		}
		h := policyHostsfile(t, "192.0.2.1 *.corp.example\n", false, zones)
		for _, name := range []string{"corp.example.", "nested.child.corp.example.", `outside\.corp.example.`} {
			for _, wire := range []bool{false, true} {
				passed := false
				next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { passed = true; ch.Cancel() })
				w := mock.NewWriter("udp", "192.0.2.1:40000")
				ch := middleware.NewChain([]middleware.Handler{h, next})
				if wire {
					ch.ResetWire(w, wireHostsRequest(t, name, dns.TypeA))
				} else {
					q := new(dns.Msg)
					q.SetQuestion(name, dns.TypeA)
					ch.Reset(w, q)
				}
				ch.Next(context.Background())
				wantMiss := scoped && name == `outside\.corp.example.`
				if passed != wantMiss || w.Written() == wantMiss {
					t.Errorf("name=%s scoped=%v wire=%v passed=%v written=%v", name, scoped, wire, passed, w.Written())
				}
			}
		}
	}
	h := policyHostsfile(t, "192.0.2.1 *.corp.example\n", false, []string{"corp.example"})
	req := wireHostsRequest(t, `outside\.corp.example.`, dns.TypeA)
	if n := testing.AllocsPerRun(100, func() {
		var buf [dnsname.MaxPresentationLength]byte
		key, ok := dnsname.AppendFoldedKey(buf[:0], req.WireName())
		if !ok {
			t.Fatal("key refused")
		}
		if _, found := lookupKeyed(h, h.getDB(), key, dns.TypeA); found {
			t.Fatal("outside wildcard hit")
		}
	}); n != 0 {
		t.Fatalf("scoped wildcard miss allocations=%v", n)
	}
}

func TestHostsfileGenericOwnerWireIdentity(t *testing.T) {
	h := policyHostsfile(t, "192.0.2.1 K.example\n192.0.2.2 corp\\046\n192.0.2.3 under_score.example\n", false, []string{"."})
	for _, name := range []string{"K.example.", `corp\..`, "under_score.example."} {
		for _, wire := range []bool{false, true} {
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{h})
			if wire {
				ch.ResetWire(w, wireHostsRequest(t, name, dns.TypeA))
			} else {
				q := new(dns.Msg)
				q.SetQuestion(name, dns.TypeA)
				packed, err := q.Pack()
				if err != nil {
					t.Fatal(err)
				}
				if err = q.Unpack(packed); err != nil {
					t.Fatal(err)
				}
				ch.Reset(w, q)
			}
			ch.Next(context.Background())
			if !w.Written() || len(w.Msg().Answer) != 1 {
				t.Fatalf("%s wire=%v missing generic owner", name, wire)
			}
			if _, err := w.Msg().Pack(); err != nil {
				t.Fatalf("%s wire=%v pack response: %v", name, wire, err)
			}
		}
	}
}

func TestHostsfilePolicyDuplicateResponseCounts(t *testing.T) {
	h := policyHostsfile(t, "192.0.2.40 primary.example. PRIMARY.EXAMPLE alias.example ALIAS.EXAMPLE. alias.example\n2001:db8::40 primary.example PRIMARY.EXAMPLE v6alias.example V6ALIAS.EXAMPLE.\n", true, []string{"example"})
	for _, tc := range []struct {
		name  string
		qtype uint16
		count int
		kind  string
		want  string
	}{
		{"primary.example.", dns.TypeA, 1, "A", "192.0.2.40"},
		{"primary.example.", dns.TypeAAAA, 1, "AAAA", "2001:db8::40"},
		{"alias.example.", dns.TypeCNAME, 1, "CNAME", "primary.example."},
		{"v6alias.example.", dns.TypeCNAME, 1, "CNAME", "primary.example."},
		{reverseName("192.0.2.40"), dns.TypePTR, 1, "PTR", "primary.example."},
		{reverseName("2001:db8::40"), dns.TypePTR, 1, "PTR", "primary.example."},
		{"primary.example.", dns.TypeCNAME, 0, "", ""},
		{"missing.example.", dns.TypeA, 0, "", ""},
	} {
		for _, wire := range []bool{false, true} {
			passed := false
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { passed = true; ch.Cancel() })
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{h, next})
			if wire {
				ch.ResetWire(w, wireHostsRequest(t, tc.name, tc.qtype))
			} else {
				q := new(dns.Msg)
				q.SetQuestion(tc.name, tc.qtype)
				ch.Reset(w, q)
			}
			ch.Next(context.Background())
			missing := tc.count == 0
			if passed != missing || w.Written() == missing {
				t.Fatalf("%s type=%d wire=%v passed=%v written=%v want missing=%v", tc.name, tc.qtype, wire, passed, w.Written(), missing)
			}
			if missing {
				continue
			}
			if !w.Msg().Authoritative {
				t.Fatalf("%s type=%d wire=%v did not receive local authoritative answer", tc.name, tc.qtype, wire)
			}
			if got := len(w.Msg().Answer); got != tc.count {
				t.Errorf("%s type=%d wire=%v answer count=%d want%d", tc.name, tc.qtype, wire, got, tc.count)
			}
			for _, rr := range w.Msg().Answer {
				if dns.TypeToString[rr.Header().Rrtype] != tc.kind {
					t.Errorf("%s type=%d wire=%v answer=%v want %s", tc.name, tc.qtype, wire, rr, tc.kind)
				}
				got := ""
				switch rr := rr.(type) {
				case *dns.A:
					got = rr.A.String()
				case *dns.AAAA:
					got = rr.AAAA.String()
				case *dns.CNAME:
					got = rr.Target
				case *dns.PTR:
					got = rr.Ptr
				}
				if got != tc.want {
					t.Errorf("%s type=%d wire=%v answer value=%q want %q", tc.name, tc.qtype, wire, got, tc.want)
				}
			}
		}
	}
}

func TestHostsfilePolicyMixedHomeFile(t *testing.T) {
	content := "192.0.2.1 router.home.arpa router.home.arpa.\n" +
		"192.0.2.2 harmonyhub.home.arpa home.home.arpa ns.home.arpa alias.home.arpa\n" +
		"127.0.0.1 localhost.localdomain localhost vyos\n" +
		"127.0.0.1 dns1.nextdns.io\n" +
		"192.0.2.4 host-.home.arpa\n" +
		"192.0.2.11 -.home.arpa alias-.home.arpa\n" +
		"192.0.2.12 -.home.arpa alias-.home.arpa\n" +
		"192.0.2.13 -.home.arpa alias-.home.arpa\n"
	h := policyHostsfile(t, content, true, []string{"home.arpa"})
	for _, tc := range []struct {
		name  string
		qtype uint16
		want  string
		miss  bool
	}{
		{"router.home.arpa.", dns.TypeA, "192.0.2.1", false},
		{"harmonyhub.home.arpa.", dns.TypeA, "192.0.2.2", false},
		{"alias.home.arpa.", dns.TypeCNAME, "harmonyhub.home.arpa.", false},
		{"2.2.0.192.in-addr.arpa.", dns.TypePTR, "harmonyhub.home.arpa.", false},
		{"localhost.", dns.TypeA, "upstream", true},
		{"localhost.localdomain.", dns.TypeA, "upstream", true},
		{"vyos.", dns.TypeA, "upstream", true},
		{"dns1.nextdns.io.", dns.TypeA, "upstream", true},
		{"host-.home.arpa.", dns.TypeA, "upstream", true},
		{"-.home.arpa.", dns.TypeA, "upstream", true},
		{"alias-.home.arpa.", dns.TypeCNAME, "upstream", true},
		{reverseName("192.0.2.11"), dns.TypePTR, "upstream", true},
		{reverseName("192.0.2.12"), dns.TypePTR, "upstream", true},
		{reverseName("192.0.2.13"), dns.TypePTR, "upstream", true},
		{reverseName("127.0.0.1"), dns.TypePTR, "upstream", true},
	} {
		for _, wire := range []bool{false, true} {
			passed := false
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { passed = true; ch.Cancel() })
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch := middleware.NewChain([]middleware.Handler{h, next})
			if wire {
				ch.ResetWire(w, wireHostsRequest(t, tc.name, tc.qtype))
			} else {
				q := new(dns.Msg)
				q.SetQuestion(tc.name, tc.qtype)
				ch.Reset(w, q)
			}
			ch.Next(context.Background())
			if passed != tc.miss {
				t.Errorf("%s type=%d wire=%v passed=%v want fallthrough=%v", tc.name, tc.qtype, wire, passed, tc.miss)
			}
			got := "upstream"
			if tc.miss {
				if w.Written() {
					t.Errorf("%s type=%d wire=%v fallthrough unexpectedly wrote a response", tc.name, tc.qtype, wire)
				}
			} else {
				if !w.Written() || !w.Msg().Authoritative {
					t.Fatalf("%s type=%d wire=%v local response not authoritative", tc.name, tc.qtype, wire)
				}
				if len(w.Msg().Answer) != 1 {
					got = fmt.Sprintf("%d answers", len(w.Msg().Answer))
				} else {
					switch rr := w.Msg().Answer[0].(type) {
					case *dns.A:
						got = rr.A.String()
					case *dns.CNAME:
						got = rr.Target
					case *dns.PTR:
						got = rr.Ptr
					}
				}
			}
			if got != tc.want {
				t.Errorf("%s type=%d wire=%v got %s want %s", tc.name, tc.qtype, wire, got, tc.want)
			}
		}
	}
}

func TestHostsfileZonesConfigLoadWireIdentity(t *testing.T) {
	labelLengths := [...]byte{3, 3, 4, 4}
	for _, prefix := range []string{"", "child."} {
		for _, spelling := range []string{"ü", `\195\188`} {
			for n := 1; n <= 4; n++ {
				zone := prefix + spelling + strings.Repeat(`\`, n) + "."
				t.Run(fmt.Sprintf("prefix=%q/spelling=%q/backslashes=%d", prefix, spelling, n), func(t *testing.T) {
					// Use the other spelling in the file to pin DNS byte identity
					// across raw UTF-8 and decimal-escaped zone settings.
					ownerSpelling := `\195\188`
					if spelling != "ü" {
						ownerSpelling = "ü"
					}
					owner := prefix + ownerSpelling + strings.Repeat(`\`, n) + "."
					hosts := fmt.Sprintf("192.0.2.31 %s\n192.0.2.32 child.%s\n192.0.2.33 different.test\n", owner, owner)
					hostsPath := createTempHostsFile(t, hosts)
					configPath := filepath.Join(t.TempDir(), "sdns.toml")
					text := fmt.Sprintf("version = %q\nipv6access = true\ndnssec = %q\nrootservers = [%q]\nhostsfile = %q\nhostsfilechecknames = false\nhostsfilezones = [%q]\ndirectory = %q\n", "1.9.0", "off", "192.0.2.53:53", hostsPath, zone, t.TempDir())
					if err := os.WriteFile(configPath, []byte(text), 0600); err != nil {
						t.Fatal(err)
					}
					cfg, err := config.Load(configPath, "1.9.0")
					if err != nil {
						t.Fatalf("config.Load rejected %q: %v", zone, err)
					}
					h := New(cfg)
					if h == nil {
						t.Fatalf("New rejected loaded zone %q", zone)
					}
					if h.watcher != nil {
						if err := h.watcher.Close(); err != nil {
							t.Fatal(err)
						}
					}

					// Construct wire bytes independently. The escaped final dot
					// must stay in its label, not become the root or truncate it.
					label := append([]byte{0xc3, 0xbc}, bytes.Repeat([]byte{92}, n/2)...)
					if n%2 != 0 {
						label = append(label, 46)
					}
					zoneWire := append([]byte{labelLengths[n-1]}, label...)
					zoneWire = append(zoneWire, 0)
					if prefix != "" {
						zoneWire = append([]byte{5, 99, 104, 105, 108, 100}, zoneWire...)
					}
					assertConfigZoneHosts(t, h, zoneWire)
				})
			}
		}
	}
}

func assertConfigZoneHosts(t *testing.T, h *Hostsfile, zoneWire []byte) {
	t.Helper()
	var keyBuf [dnsname.MaxPresentationLength]byte
	zoneKey, ok := dnsname.AppendFoldedKey(keyBuf[:0], zoneWire)
	if !ok {
		t.Fatal("expected zone wire name refused")
	}
	if len(h.zones) != 1 || h.zones[0] != string(zoneKey)+"." {
		t.Fatalf("loaded zones=%q want wire key %q", h.zones, string(zoneKey)+".")
	}
	if h.zones[0] == "." {
		t.Fatal("non-root configured zone collapsed to unrestricted root")
	}
	childWire := append([]byte{5}, []byte("child")...)
	childWire = append(childWire, zoneWire...)
	var childBuf [dnsname.MaxPresentationLength]byte
	childKey, ok := dnsname.AppendFoldedKey(childBuf[:0], childWire)
	if !ok {
		t.Fatal("expected child wire name refused")
	}
	db := h.getDB()
	if db.hosts[string(zoneKey)] == nil || db.hosts[string(childKey)] == nil || db.hosts["different.test"] != nil {
		t.Fatalf("hosts do not match zone wire identity: keys=%v", db.hosts)
	}
}

func TestHostsfileRejectsStructurallyInvalidConfiguredZone(t *testing.T) {
	if h := New(&config.Config{HostsFile: createTempHostsFile(t, "192.0.2.1 valid.example\n"), HostsFileZones: []string{`invalid\`}}); h != nil {
		if h.watcher != nil {
			_ = h.watcher.Close()
		}
		t.Fatal("trailing escape zone was accepted")
	}
}
