package server

import (
	"context"
	"net"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"fmt"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
	"github.com/semihalev/sdns/internal/mock"
)

// The Z2a exact-entry hit classes: every shape here must serve its warm
// hit through the wire path allocation-free AND byte-equivalently to the
// Msg path's answer for the same entry. The stub stands in for the
// resolver; the class is in the stored response's shape.

func classSigned(name string, qtype uint16) []dns.RR {
	a := &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, 99),
	}
	sig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 300},
		TypeCovered: qtype,
		Algorithm:   dns.RSASHA256,
		Labels:      2,
		OrigTtl:     300,
		Expiration:  uint32(time.Now().Add(24 * time.Hour).Unix()), //nolint:gosec // test fixture
		Inception:   uint32(time.Now().Add(-time.Hour).Unix()),     //nolint:gosec // test fixture
		KeyTag:      12345,
		SignerName:  "zero.test.",
		Signature:   "MEQCIF5edm5vY2Vhbm9ncmFwaHkgaXMgZnVuIQIgTm90QVJlYWxTaWc=",
	}
	return []dns.RR{a, sig}
}

func cnameRR(owner, target string) dns.RR {
	return &dns.CNAME{
		Hdr:    dns.RR_Header{Name: owner, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
		Target: target,
	}
}

func aRR(owner string, b byte) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: owner, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
		A:   net.IPv4(192, 0, 2, b),
	}
}

// chaseStub answers per question name so the resolver stand-in can store
// alias-only entries and their targets as separate cache entries.
func chaseStub(answers map[string][]dns.RR) func(req *dns.Msg) *dns.Msg {
	return func(req *dns.Msg) *dns.Msg {
		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.RecursionAvailable = true
		resp.Answer = answers[req.Question[0].Name]
		return resp
	}
}

func TestServeRawHitClasses(t *testing.T) {
	classes := []struct {
		name        string
		query       func() *dns.Msg
		reply       func(req *dns.Msg) *dns.Msg
		msgFallback bool // class not yet wire-served; only parity is gated
	}{
		{
			// Real additional records survive admission and the TTL walk.
			name: "additional-section",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("mx.zero.test.", dns.TypeMX)
				m.SetEdns0(1232, false)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.RecursionAvailable = true
				resp.Answer = []dns.RR{&dns.MX{
					Hdr:        dns.RR_Header{Name: "mx.zero.test.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 10,
					Mx:         "mail.zero.test.",
				}}
				resp.Extra = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: "mail.zero.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(192, 0, 2, 25),
				}}
				return resp
			},
		},
		{
			// An explicit RRSIG question keeps its signatures for DO=0.
			name: "rrsig-question",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("sig.zero.test.", dns.TypeRRSIG)
				m.SetEdns0(1232, false)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.RecursionAvailable = true
				resp.Answer = classSigned("sig.zero.test.", dns.TypeA)[1:]
				return resp
			},
		},
		{
			// A DO=1 client gets the signed body.
			name: "signed-do",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("signed.zero.test.", dns.TypeA)
				m.SetEdns0(1232, true)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.RecursionAvailable = true
				resp.Answer = classSigned("signed.zero.test.", dns.TypeA)
				return resp
			},
		},
		{
			// A DO=0 client gets the stripped body of the same signed entry.
			name: "signed-nodo",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("signed.zero.test.", dns.TypeA)
				m.SetEdns0(1232, false)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.RecursionAvailable = true
				resp.Answer = classSigned("signed.zero.test.", dns.TypeA)
				return resp
			},
		},
		{
			// A cached Extended DNS Error is re-attached to the reply OPT.
			name: "ede",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("stale.zero.test.", dns.TypeA)
				m.SetEdns0(1232, false)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetReply(req)
				resp.RecursionAvailable = true
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: "stale.zero.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
					A:   net.IPv4(192, 0, 2, 42),
				}}
				opt := new(dns.OPT)
				opt.Hdr.Name = "."
				opt.Hdr.Rrtype = dns.TypeOPT
				opt.SetUDPSize(1232)
				opt.Option = append(opt.Option, &dns.EDNS0_EDE{
					InfoCode:  dns.ExtendedErrorCodeStaleAnswer,
					ExtraText: "stale answer served from cache",
				})
				resp.Extra = append(resp.Extra, opt)
				return resp
			},
		},
		{
			// A cache-contained alias: the composer walks the target entry
			// and answers without a decoded message.
			name: "cname-chase",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("chase.zero.test.", dns.TypeA)
				m.SetEdns0(1232, false)
				return m
			},
			reply: chaseStub(map[string][]dns.RR{
				"chase.zero.test.":  {cnameRR("chase.zero.test.", "target.zero.test.")},
				"target.zero.test.": {aRR("target.zero.test.", 61)},
			}),
		},
		{
			name: "cname-chase-2hop",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("hop.zero.test.", dns.TypeA)
				m.SetEdns0(1232, false)
				return m
			},
			reply: chaseStub(map[string][]dns.RR{
				"hop.zero.test.": {cnameRR("hop.zero.test.", "mid.zero.test.")},
				"mid.zero.test.": {cnameRR("mid.zero.test.", "end.zero.test.")},
				"end.zero.test.": {aRR("end.zero.test.", 62)},
			}),
		},
		{
			// A signed chain for a DO client: RRSIGs are copied verbatim
			// (their signer names are never compressed).
			name: "cname-chase-signed",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("schase.zero.test.", dns.TypeA)
				m.SetEdns0(1232, true)
				return m
			},
			reply: chaseStub(map[string][]dns.RR{
				"schase.zero.test.":  {cnameRR("schase.zero.test.", "starget.zero.test.")},
				"starget.zero.test.": classSigned("starget.zero.test.", dns.TypeA),
			}),
		},
		{
			// An RFC 9520 cached failure: the first serve records, the
			// warm ones synthesize the EDE-13 SERVFAIL from bytes.
			name: "failure-cache",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("broken.zero.test.", dns.TypeA)
				m.SetEdns0(1232, false)
				return m
			},
			reply: func(req *dns.Msg) *dns.Msg {
				resp := new(dns.Msg)
				resp.SetRcode(req, dns.RcodeServerFailure)
				resp.RecursionAvailable = true
				return resp
			},
		},
		{
			// An MX terminal carries a compressible rdata name: the
			// composer declines and the Msg path answers, unchanged.
			name: "cname-chase-mx-fallback",
			query: func() *dns.Msg {
				m := new(dns.Msg)
				m.SetQuestion("mxchase.zero.test.", dns.TypeMX)
				m.SetEdns0(1232, false)
				return m
			},
			reply: chaseStub(map[string][]dns.RR{
				"mxchase.zero.test.": {cnameRR("mxchase.zero.test.", "mxend.zero.test.")},
				"mxend.zero.test.": {&dns.MX{
					Hdr:        dns.RR_Header{Name: "mxend.zero.test.", Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
					Preference: 5,
					Mx:         "mail.zero.test.",
				}},
			}),
			msgFallback: true,
		},
	}

	for _, tc := range classes {
		t.Run(tc.name, func(t *testing.T) {
			s := newHitChainServerWith(t, tc.reply)
			q := tc.query()
			raw, err := q.Pack()
			if err != nil {
				t.Fatalf("pack: %v", err)
			}

			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 30), Port: 4242}}
			// Warm miss, then the wire hit under test.
			for i := 0; i < 2; i++ {
				job.wrote = job.wrote[:0]
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatalf("serve %d not handled", i)
				}
			}
			wireResp := new(dns.Msg)
			if err := wireResp.Unpack(job.wrote); err != nil {
				t.Fatalf("wire reply unpack: %v", err)
			}

			// The same warm entry through the Msg path: a mock transport has
			// no wire capability, so the cache serves this hit via ToMsg.
			mw := mock.NewWriter("udp", "203.0.113.30:4242")
			s.ServeMsg(context.Background(), mw, q.Copy())
			msgResp := mw.Msg()
			if msgResp == nil {
				t.Fatal("msg path wrote nothing")
			}

			if diff := respDiff(wireResp, msgResp); diff != "" {
				t.Fatalf("wire and Msg answers diverge for %s:\n%s\n wire: %v\n msg:  %v",
					tc.name, diff, wireResp, msgResp)
			}

			if tc.msgFallback {
				return
			}
			// The class gate: the warm wire hit allocates nothing.
			//
			// The outcome counters are read around the measurement so a
			// failure says which decision was taken, not just that the
			// cost was wrong. A wire hit that quietly starts taking the
			// Msg path costs about a hundred objects and looks identical
			// to a regression in the byte path itself; the counters are
			// the difference between the two.
			before := wireOutcomes()
			allocs := testing.AllocsPerRun(100, func() {
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("hit serve not handled")
				}
			})
			if allocs != 0 {
				// Say where, not just how many. The outcome counters
				// separate "the byte path declined" from "the byte path
				// served and allocated"; the sites say which line did it,
				// which is the difference between a report and a lead.
				sites := allocSites(20, func() {
					if !s.ServeRaw(job, raw, time.Now()) {
						t.Fatal("hit serve not handled")
					}
				})
				for _, line := range sites {
					t.Log("   ", line)
				}
				t.Fatalf("class %s: warm wire hit allocated %.2f objects per serve; "+
					"byte-path outcomes over the measurement: %s",
					tc.name, allocs, wireOutcomeDelta(before))
			}
		})
	}
}

// respDiff compares the client-visible reply facts, tolerating TTL drift
// between the two serves and ignoring section order.
func respDiff(a, b *dns.Msg) string {
	var diffs []string
	if a.Rcode != b.Rcode {
		diffs = append(diffs, "rcode")
	}
	if a.RecursionAvailable != b.RecursionAvailable ||
		a.Truncated != b.Truncated ||
		a.AuthenticatedData != b.AuthenticatedData ||
		a.Authoritative != b.Authoritative {
		diffs = append(diffs, "flags")
	}
	if sectionKey(a.Answer) != sectionKey(b.Answer) {
		diffs = append(diffs, "answer")
	}
	if sectionKey(a.Ns) != sectionKey(b.Ns) {
		diffs = append(diffs, "authority")
	}
	if sectionKey(withoutOPT(a.Extra)) != sectionKey(withoutOPT(b.Extra)) {
		diffs = append(diffs, "additional")
	}
	aOPT, bOPT := a.IsEdns0(), b.IsEdns0()
	if (aOPT == nil) != (bOPT == nil) {
		diffs = append(diffs, "opt-presence")
	} else if aOPT != nil {
		if aOPT.Do() != bOPT.Do() {
			diffs = append(diffs, "opt-do")
		}
		if optionSetKey(aOPT) != optionSetKey(bOPT) {
			diffs = append(diffs, "opt-options")
		}
	}
	return strings.Join(diffs, ", ")
}

func withoutOPT(rrs []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(rrs))
	for _, rr := range rrs {
		if rr.Header().Rrtype == dns.TypeOPT {
			continue
		}
		out = append(out, rr)
	}
	return out
}

// sectionKey renders a section with TTLs zeroed, order-insensitively.
func sectionKey(rrs []dns.RR) string {
	lines := make([]string, 0, len(rrs))
	for _, rr := range rrs {
		cp := dns.Copy(rr)
		cp.Header().Ttl = 0
		lines = append(lines, cp.String())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func optionSetKey(opt *dns.OPT) string {
	lines := make([]string, 0, len(opt.Option))
	for _, o := range opt.Option {
		lines = append(lines, o.String())
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// wireOutcomes reads the cache's byte-path outcome counters out of the
// default prometheus registry. The counters live in another package and
// are unexported there; the registry is the seam that is already public,
// and a test that can name the decline is worth the gather.
func wireOutcomes() map[string]float64 {
	metric.FlushAll()
	out := map[string]float64{}
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return out
	}
	for _, f := range families {
		if f.GetName() != "dns_cache_wire_fastpath_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "outcome" {
					out[l.GetValue()] = m.GetCounter().GetValue()
				}
			}
		}
	}
	return out
}

// wireOutcomeDelta renders what changed since before.
func wireOutcomeDelta(before map[string]float64) string {
	var parts []string
	for outcome, now := range wireOutcomes() {
		if d := now - before[outcome]; d != 0 {
			parts = append(parts, fmt.Sprintf("%s=%.0f", outcome, d))
		}
	}
	if len(parts) == 0 {
		return "none recorded"
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// allocSites re-runs fn with every allocation profiled and returns the
// sites that allocated, largest first.
//
// It exists because a class gate that fails says only how many objects
// were allocated, and the interesting question is always which line. The
// profiler is left off until it is needed: enabling it for the whole
// binary would slow every test to buy something only a failure uses.
func allocSites(runs int, fn func()) []string {
	prevRate := runtime.MemProfileRate
	runtime.MemProfileRate = 1
	defer func() { runtime.MemProfileRate = prevRate }()

	runtime.GC()
	before := allocProfile()
	for range runs {
		fn()
	}
	runtime.GC()

	type site struct {
		objects int64
		where   string
	}
	var grown []site
	for key, now := range allocProfile() {
		if now.measuring {
			// The snapshot walks thousands of records and allocates while
			// doing it. Left in, it buries the site being looked for
			// under its own, which is exactly what it did the first time
			// this ran.
			continue
		}
		if delta := now.objects - before[key].objects; delta > 0 {
			grown = append(grown, site{delta, now.where})
		}
	}
	sort.Slice(grown, func(i, j int) bool { return grown[i].objects > grown[j].objects })

	out := make([]string, 0, len(grown))
	for i, s := range grown {
		if i == 8 {
			break
		}
		out = append(out, fmt.Sprintf("%d× %s", s.objects, s.where))
	}
	return out
}

type profiledSite struct {
	objects   int64
	where     string
	measuring bool // allocated by this diagnostic rather than by the server
}

// allocProfile snapshots the live allocation profile keyed by stack,
// naming each site by its first few frames outside the runtime.
func allocProfile() map[string]profiledSite {
	n, _ := runtime.MemProfile(nil, true)
	var records []runtime.MemProfileRecord
	for {
		records = make([]runtime.MemProfileRecord, n+64)
		var ok bool
		if n, ok = runtime.MemProfile(records, true); ok {
			records = records[:n]
			break
		}
	}

	sites := make(map[string]profiledSite, len(records))
	for i := range records {
		stack := records[i].Stack()
		var key strings.Builder
		for _, pc := range stack {
			fmt.Fprintf(&key, "%x,", pc)
		}
		var trail []string
		var measuring bool
		frames := runtime.CallersFrames(stack)
		for {
			f, more := frames.Next()
			switch {
			case strings.HasSuffix(f.Function, ".allocProfile"):
				// Only the snapshot itself. Filtering on the driver too
				// would remove everything, since the work being measured
				// is called from it.
				measuring = true
			case !strings.HasPrefix(f.Function, "runtime.") && len(trail) < 3:
				trail = append(trail, fmt.Sprintf("%s (%s:%d)",
					f.Function, filepath.Base(f.File), f.Line))
			}
			if !more {
				break
			}
		}
		sites[key.String()] = profiledSite{
			objects:   records[i].AllocObjects,
			where:     strings.Join(trail, " ← "),
			measuring: measuring,
		}
	}
	return sites
}
