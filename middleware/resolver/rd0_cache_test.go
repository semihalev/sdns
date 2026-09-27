package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
)

// askRD is edeClient.ask with the client's RD bit chosen.
func (c *edeClient) askRD(name string, qtype uint16, rd, wireBorn bool) *dns.Msg {
	c.t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, qtype)
	q.SetEdns0(1232, true)
	q.RecursionDesired = rd
	w := mock.NewWriter("udp", "127.0.0.1:0")
	ch := middleware.NewChain(c.client)
	if wireBorn {
		raw, err := q.Pack()
		if err != nil {
			c.t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			c.t.Fatal("eligible query refused by ParseWire")
		}
		ch.ResetWire(w, req)
		ch.AllowDirectPack()
	} else {
		ch.Reset(w, q)
	}
	ch.Next(context.Background())
	if !w.Written() {
		c.t.Fatal("no reply")
	}
	return w.Msg()
}

// A question that does not desire recursion is answered from the cache,
// through the EDNS layer, the cache and the resolver, wire-born and
// decoded: what the cache holds is served, RD echoed as the client sent
// it, and what it does not hold is SERVFAIL with an EDE saying so, the
// authority never asked. An alias whose target is not cached is not
// completed by resolving it either.
func TestNonRecursiveQuestionsAreAnsweredFromTheCache(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	zone.Serve(mustRR(t, "www.signed. 300 IN A 192.0.2.45"))
	cname := mustRR(t, "alias.signed. 300 IN CNAME target.signed.")
	zone.server.serve("alias.signed.", dns.TypeA, cname, zone.key.sign(t, []dns.RR{cname}))
	zone.Serve(mustRR(t, "target.signed. 300 IN A 192.0.2.46"))
	c := newEDEClient(t, net)

	warm := c.askRD("www.signed.", dns.TypeA, true, false)
	if warm.Rcode != dns.RcodeSuccess || !warm.AuthenticatedData {
		t.Fatalf("warming: %s AD=%v, want the validated answer", dns.RcodeToString[warm.Rcode], warm.AuthenticatedData)
	}

	for _, wireBorn := range []bool{false, true} {
		asked := zone.asked("www.signed.", dns.TypeA)
		resp := c.askRD("www.signed.", dns.TypeA, false, wireBorn)
		if resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 || !resp.AuthenticatedData {
			t.Fatalf("cached, RD=0, wire-born=%v: %s AD=%v %v, want the cached answer",
				wireBorn, dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, resp.Answer)
		}
		if resp.RecursionDesired {
			t.Fatalf("cached, RD=0, wire-born=%v: reply RD=1, want the client's RD echoed", wireBorn)
		}
		if zone.asked("www.signed.", dns.TypeA) != asked {
			t.Fatalf("cached, RD=0, wire-born=%v: the authority was asked", wireBorn)
		}
	}

	for _, wireBorn := range []bool{false, true} {
		for _, name := range []string{"missing.signed.", "alias.signed."} {
			resp := c.askRD(name, dns.TypeA, false, wireBorn)
			if resp.Rcode != dns.RcodeServerFailure || resp.RecursionDesired {
				t.Fatalf("%s uncached, RD=0, wire-born=%v: %s RD=%v, want SERVFAIL with RD echoed",
					name, wireBorn, dns.RcodeToString[resp.Rcode], resp.RecursionDesired)
			}
			if got := edeCodes(resp); len(got) != 1 || got[0] != dns.ExtendedErrorCodeOther {
				t.Fatalf("%s uncached, RD=0, wire-born=%v: EDE %v, want exactly EDE 0", name, wireBorn, got)
			}
		}
	}
	for _, name := range []string{"missing.signed.", "alias.signed.", "target.signed."} {
		if n := zone.asked(name, dns.TypeA); n != 0 {
			t.Fatalf("%s was resolved %d times for questions that did not desire recursion", name, n)
		}
	}

	// The alias cached, its target not: the chase stays in the cache too.
	if resp := c.askRD("alias.signed.", dns.TypeA, true, false); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) < 2 {
		t.Fatalf("warming the alias: %s %v", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
	c.cache.Purge(dns.Question{Name: "target.signed.", Qtype: dns.TypeA, Qclass: dns.ClassINET})
	asked := zone.asked("target.signed.", dns.TypeA)
	for _, wireBorn := range []bool{false, true} {
		if resp := c.askRD("alias.signed.", dns.TypeA, false, wireBorn); resp.Rcode != dns.RcodeServerFailure || resp.RecursionDesired {
			t.Fatalf("alias cached, target not, RD=0, wire-born=%v: %s RD=%v %v, want SERVFAIL with RD echoed",
				wireBorn, dns.RcodeToString[resp.Rcode], resp.RecursionDesired, resp.Answer)
		}
	}
	if n := zone.asked("target.signed.", dns.TypeA) - asked; n != 0 {
		t.Fatalf("the alias's target was resolved %d times for a question that did not desire recursion", n)
	}
	// With RD=1 the same alias completes, the target resolved again.
	if resp := c.askRD("alias.signed.", dns.TypeA, true, false); resp.Rcode != dns.RcodeSuccess || len(resp.Answer) < 2 {
		t.Fatalf("alias, RD=1: %s %v, want the target resolved", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

// The root stays resolvable without RD for a client's own question only: an
// alias whose target is the root is completed from the cache, like any
// other, and the root is not asked on the client's behalf.
func TestNonRecursiveAliasToTheRootIsNotResolved(t *testing.T) {
	net := newHermeticNet(t)
	net.Delegate("signed.")
	c := newEDEClient(t, net)

	// The alias alone in the cache, its target not: the shape a chase
	// completes.
	q := dns.Question{Name: "toroot.signed.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET}
	alias := new(dns.Msg)
	alias.SetQuestion(q.Name, q.Qtype)
	alias.Response = true
	alias.RecursionAvailable = true
	alias.Answer = []dns.RR{mustRR(t, "toroot.signed. 300 IN CNAME .")}
	c.cache.Set(answercache.CacheKey{Question: q}.Hash(), alias)
	asked := net.root.asked(".", dns.TypeTXT)
	for _, wireBorn := range []bool{false, true} {
		resp := c.askRD("toroot.signed.", dns.TypeTXT, false, wireBorn)
		if resp.Rcode != dns.RcodeServerFailure || resp.RecursionDesired {
			t.Fatalf("alias to the root, RD=0, wire-born=%v: %s RD=%v %v, want SERVFAIL with RD echoed",
				wireBorn, dns.RcodeToString[resp.Rcode], resp.RecursionDesired, resp.Answer)
		}
	}
	if n := net.root.asked(".", dns.TypeTXT) - asked; n != 0 {
		t.Fatalf("the root was asked %d times for an alias chased without recursion", n)
	}
}
