package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	answercache "github.com/semihalev/sdns/middleware/cache"
)

// Only an answer made of the signatures at the question name is served
// unvalidated as such. An RRset no signature covers riding along, an
// unsigned TXT slipped into the answer to an RRSIG question, sends the whole
// answer through ordinary validation, which refuses it.
func TestRRSIGQuestionCarriesNothingElseUnvalidated(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	a := mustRR(t, "www.signed. 300 IN A 192.0.2.45")
	zone.Serve(a)
	zone.server.serve("www.signed.", dns.TypeRRSIG,
		zone.key.sign(t, []dns.RR{a}), mustRR(t, `www.signed. 300 IN TXT "injected"`))
	handler := net.Handler()

	warm := new(dns.Msg)
	warm.SetQuestion("www.signed.", dns.TypeA)
	warm.SetEdns0(1232, true)
	if resp := handler.handle(context.Background(), warm); resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
		t.Fatalf("warming: %s AD=%v, want the validated A", dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.signed.", dns.TypeRRSIG)
	req.SetEdns0(1232, true)
	if resp := handler.handle(context.Background(), req); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%s %v, want the answer carrying an unsigned A refused", dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

// The signatures are the question's own only in the question's class: an
// answer to an IN question made of same-named signatures in another class
// is not the answer to it, and takes the ordinary path, which refuses it.
func TestRRSIGQuestionTakesOnlyItsOwnClass(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	a := mustRR(t, "www.signed. 300 IN A 192.0.2.45")
	zone.Serve(a)
	chaos := zone.key.sign(t, []dns.RR{a})
	chaos.Header().Class = dns.ClassCHAOS
	zone.server.serve("www.signed.", dns.TypeRRSIG, chaos)
	handler := net.Handler()

	warm := new(dns.Msg)
	warm.SetQuestion("www.signed.", dns.TypeA)
	warm.SetEdns0(1232, true)
	if resp := handler.handle(context.Background(), warm); resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
		t.Fatalf("warming: %s AD=%v, want the validated A", dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
	}

	req := new(dns.Msg)
	req.SetQuestion("www.signed.", dns.TypeRRSIG)
	req.SetEdns0(1232, true)
	if resp := handler.handle(context.Background(), req); resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%s %v, want the CH signatures refused as the answer to an IN question",
			dns.RcodeToString[resp.Rcode], resp.Answer)
	}
}

// A question for the RRSIGs at a name in a signed zone is answered with
// them. The RRSIG RRset is not itself signed, so it cannot be validated and
// carries no AD, but it is no failure either: refusing it as bogus answered
// SERVFAIL, and cached that, for a question every signed name can answer.
// DO=0 keeps the type the question named (RFC 4035 §3.2.1).
func TestRRSIGQuestionIsAnsweredUnvalidated(t *testing.T) {
	net := newHermeticNet(t)
	zone := net.Delegate("signed.")
	for _, owner := range []string{"www.signed.", "signed."} {
		a := mustRR(t, owner+" 300 IN A 192.0.2.45")
		zone.Serve(a)
		zone.server.serve(owner, dns.TypeRRSIG, zone.key.sign(t, []dns.RR{a}))
	}

	cfg := net.Config()
	cfg.CacheSize = 1024
	handler := net.handlerWithConfig(cfg)
	cache := answercache.New(cfg)
	handlers := []middleware.Handler{cache, handler}
	var queryer middleware.Queryer = pipelineQueryer{handlers: handlers}
	handler.resolver.queryer.Store(&queryer)
	cache.SetQueryer(queryer)

	// The zone's delegation is learned, DS and all, by an ordinary question
	// first, as it is on a running resolver. Asked cold, the RRSIG question
	// learns the delegation without its DS and nothing is validated.
	for _, owner := range []string{"www.signed.", "signed."} {
		req := new(dns.Msg)
		req.SetQuestion(owner, dns.TypeA)
		req.SetEdns0(1232, true)
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(handlers)
		ch.Reset(w, req)
		ch.Next(context.Background())
		if resp := w.Msg(); resp == nil || resp.Rcode != dns.RcodeSuccess || !resp.AuthenticatedData {
			t.Fatalf("warming %s: %v, want the validated A", owner, resp)
		}
	}

	for _, pass := range []struct {
		name  string
		owner string
		do    bool
	}{
		{"below the apex DO=1", "www.signed.", true},
		{"below the apex DO=0", "www.signed.", false},
		{"below the apex DO=1 again, cached", "www.signed.", true},
		{"zone apex DO=1", "signed.", true},
		{"zone apex DO=0", "signed.", false},
		{"zone apex DO=1 again, cached", "signed.", true},
	} {
		req := new(dns.Msg)
		req.SetQuestion(pass.owner, dns.TypeRRSIG)
		req.SetEdns0(1232, pass.do)
		w := mock.NewWriter("udp", "127.0.0.1:0")
		ch := middleware.NewChain(handlers)
		ch.Reset(w, req)
		ch.Next(context.Background())
		if !w.Written() {
			t.Fatalf("%s: no reply", pass.name)
		}
		resp := w.Msg()
		if resp.Rcode != dns.RcodeSuccess || resp.AuthenticatedData {
			t.Fatalf("%s: %s AD=%v, want NOERROR without AD", pass.name,
				dns.RcodeToString[resp.Rcode], resp.AuthenticatedData)
		}
		sigs := 0
		for _, rr := range resp.Answer {
			if sig, ok := rr.(*dns.RRSIG); ok && sig.TypeCovered == dns.TypeA {
				sigs++
			}
		}
		if sigs != 1 {
			t.Fatalf("%s: answer %v, want the RRSIG covering A", pass.name, resp.Answer)
		}
	}
}
