package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

// failureCauseChain is edns→cache→a terminal that fails every question it
// sees with the given EDE, none when hasEDE is false, the way the live
// chain wires them.
type failureCauseChain struct {
	c        *Cache
	e        *edns.EDNS
	terminal middleware.Handler
	calls    int
}

func newFailureCauseChain(t *testing.T, hasEDE bool, code uint16, text string) *failureCauseChain {
	t.Helper()
	cfg := makeTestConfig()
	cfg.RateLimit = 0
	f := &failureCauseChain{c: New(cfg), e: edns.New(cfg)}
	t.Cleanup(f.c.Stop)
	f.terminal = middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		f.calls++
		resp := new(dns.Msg)
		resp.SetReply(ch.Request.Msg())
		resp.Rcode = dns.RcodeServerFailure
		resp.SetEdns0(1232, true)
		if hasEDE {
			dnsutil.SetEDE(resp, code, text)
		}
		if err := ch.Writer.WriteMsg(resp); err != nil {
			t.Errorf("WriteMsg() error = %v", err)
		}
		ch.Cancel()
	})
	return f
}

// ask sends one EDNS question, wire-born or decoded, and reports the reply
// and whether the byte path composed it.
func (f *failureCauseChain) ask(t *testing.T, name string, wireBorn bool) (*dns.Msg, bool) {
	t.Helper()
	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = true
	q.SetEdns0(1232, true)
	writer := mock.NewWriter("udp", "198.51.100.9:40000")
	ch := middleware.NewChain([]middleware.Handler{f.e, f.c, f.terminal})
	if wireBorn {
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		req := new(middleware.Request)
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatalf("eligible query %s refused", name)
		}
		ch.ResetWire(writer, req)
	} else {
		ch.Reset(writer, q)
	}
	ch.AllowDirectPack()
	before := wireFailureServed.Value()
	ch.Next(context.Background())
	if !writer.Written() {
		t.Fatalf("no reply for %s", name)
	}
	resp := writer.Msg()
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("%s answered %s, want SERVFAIL", name, dns.RcodeToString[resp.Rcode])
	}
	return resp, wireFailureServed.Value() > before
}

func onlyEDE(t *testing.T, step string, resp *dns.Msg, code uint16, text string) {
	t.Helper()
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatalf("%s: no OPT on a reply to an EDNS client", step)
	}
	var edes []*dns.EDNS0_EDE
	for _, o := range opt.Option {
		if ede, ok := o.(*dns.EDNS0_EDE); ok {
			edes = append(edes, ede)
		}
	}
	if len(edes) != 1 || edes[0].InfoCode != code || edes[0].ExtraText != text {
		t.Fatalf("%s: EDE %+v, want exactly code %d text %q", step, edes, code, text)
	}
}

// A cached failure says why it failed: the EDE the failure carried when it
// was recorded, code and text, on the byte path and the Msg path alike. A
// failure that carried none says Cached Error. One EDE, never a second.
func TestCachedFailureReplaysItsCause(t *testing.T) {
	for _, tc := range []struct {
		name     string
		hasEDE   bool
		code     uint16
		text     string
		wantCode uint16
		wantText string
	}{
		{"bogus", true, dns.ExtendedErrorCodeDNSBogus, "RRSIG does not verify",
			dns.ExtendedErrorCodeDNSBogus, "RRSIG does not verify"},
		{"signature not yet valid", true, dns.ExtendedErrorCodeSignatureNotYetValid, "",
			dns.ExtendedErrorCodeSignatureNotYetValid, ""},
		{"no cause", false, 0, "",
			dns.ExtendedErrorCodeCachedError, failureCacheEDEText},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFailureCauseChain(t, tc.hasEDE, tc.code, tc.text)
			const name = "fail.example."
			first, _ := f.ask(t, name, false)
			if tc.hasEDE {
				onlyEDE(t, "first", first, tc.code, tc.text)
			}
			for _, wireBorn := range []bool{true, false} {
				resp, byWire := f.ask(t, name, wireBorn)
				if byWire != wireBorn {
					t.Fatalf("wire-born=%v served by the byte path=%v", wireBorn, byWire)
				}
				onlyEDE(t, "cached", resp, tc.wantCode, tc.wantText)
			}
			if f.calls != 1 {
				t.Fatalf("terminal reached %d times, want the first ask only", f.calls)
			}
		})
	}
}

// A cause whose text would carry the reply past the client's limit is
// the Msg path's to trim, the byte path does not send it.
func TestCachedFailureCausePastTheLimitLeavesTheBytePath(t *testing.T) {
	f := newFailureCauseChain(t, true, dns.ExtendedErrorCodeDNSBogus, strings.Repeat("x", 1300))
	const name = "long.example."
	f.ask(t, name, false)
	if _, byWire := f.ask(t, name, true); byWire {
		t.Fatal("a cause past the client's limit was served from bytes")
	}
	if f.calls != 1 {
		t.Fatalf("terminal reached %d times, want the first ask only", f.calls)
	}
}

// A validation verdict replaces the cause of a failure already recorded
// in its generation, it is why the data failed; any other failure in the
// generation leaves the cause as it is, and a renewal takes the new one.
func TestFailureCauseFollowsTheGeneration(t *testing.T) {
	clock := newFailureFakeClock()
	fc := newFailureTestCache(t, 16, clock)
	key := FailureQuestionKey{Question: dns.Question{Name: "gen.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
	timeout := failureCause{code: dns.ExtendedErrorCodeNoReachableAuthority, text: "timeout", set: true}
	bogus := failureCause{code: dns.ExtendedErrorCodeDNSBogus, text: "bogus", set: true}

	want := func(step string, c failureCause) {
		t.Helper()
		hit, ok := fc.Lookup(key)
		if !ok {
			t.Fatalf("%s: no active failure", step)
		}
		if hit.cause != c {
			t.Fatalf("%s: cause %+v, want %+v", step, hit.cause, c)
		}
	}

	fc.recordQuestion(key, FailureProvenance("response"), nil, timeout)
	want("first", timeout)
	fc.recordQuestion(key, FailureProvenance("response"), nil, failureCause{})
	want("same generation, no verdict", timeout)
	fc.recordQuestion(key, FailureProvenanceValidation, nil, bogus)
	want("validation upgrade", bogus)
	fc.recordQuestion(key, FailureProvenanceValidation, nil, timeout)
	want("verdict already in", bogus)

	hit, _ := fc.Lookup(key)
	clock.Advance(hit.RetryAfter.Sub(clock.Now()) + time.Millisecond)
	fc.recordQuestion(key, FailureProvenance("response"), nil, timeout)
	want("renewal", timeout)
}

// The byte path serves a recorded cause without allocating.
func TestCachedFailureCauseServesWithoutAllocating(t *testing.T) {
	f := newFailureCauseChain(t, true, dns.ExtendedErrorCodeDNSBogus, "RRSIG does not verify")
	const name = "alloc.example."
	f.ask(t, name, false)

	q := new(dns.Msg)
	q.SetQuestion(name, dns.TypeA)
	q.RecursionDesired = true
	q.SetEdns0(1232, true)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var meta middleware.ResponseMeta
	ctx := middleware.WithResponseMeta(context.Background(), &meta)
	writer := &leaseSink{Writer: mock.NewWriter("udp", "198.51.100.9:40000")}
	req := new(middleware.Request)
	ch := middleware.NewChain([]middleware.Handler{f.e, f.c, f.terminal})
	serve := func() {
		if !req.ParseWire(raw, time.Now(), nil) {
			t.Fatal("eligible query refused")
		}
		ch.ResetWire(writer, req)
		ch.AllowDirectPack()
		ch.Next(ctx)
	}
	before := wireFailureServed.Value()
	serve()
	if wireFailureServed.Value() == before {
		t.Fatal("the cached failure did not take the byte path")
	}
	if allocs := testing.AllocsPerRun(200, serve); allocs != 0 {
		t.Fatalf("byte-path failure serve allocated %.2f objects per reply", allocs)
	}
}
