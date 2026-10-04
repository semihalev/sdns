package block_aaaa

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/edns"
)

func TestNew(t *testing.T) {
	if got := New(&config.Config{}); got != nil {
		t.Fatalf("disabled constructor = %v, want typed nil", got)
	}
	b := New(&config.Config{BlockAAAA: true})
	if b == nil || b.Name() != "block_aaaa" || !b.ClientOnly() {
		t.Fatalf("enabled constructor = %+v", b)
	}
}

func request(t *testing.T, q *dns.Msg) *middleware.Request {
	t.Helper()
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	r := new(middleware.Request)
	if !r.ParseWire(raw, time.Time{}, nil) {
		t.Fatal("ParseWire rejected query")
	}
	return r
}

func query(qtype uint16) *dns.Msg {
	q := new(dns.Msg)
	q.SetQuestion("MiXeD.Example.", qtype)
	q.Id = 4321
	return q
}

func TestSuppressionWireAndDecoded(t *testing.T) {
	for _, wire := range []bool{false, true} {
		for _, proto := range []string{"udp", "tcp"} {
			for _, addr := range []string{"192.0.2.1:40000", "[2001:db8::1]:40000"} {
				for _, rd := range []bool{false, true} {
					for _, cd := range []bool{false, true} {
						for _, optMode := range []string{"none", "edns", "do"} {
							t.Run(fmt.Sprintf("wire=%v/%s/%s/rd=%v/cd=%v/%s", wire, proto, addr, rd, cd, optMode), func(t *testing.T) {
								q := query(dns.TypeAAAA)
								q.RecursionDesired, q.CheckingDisabled, q.AuthenticatedData = rd, cd, true
								if optMode != "none" {
									q.SetEdns0(1232, optMode == "do")
								}
								wantQuestion := append([]dns.Question(nil), q.Question...)
								cfg := &config.Config{BlockAAAA: true}
								forbidden := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
									t.Fatal("suppressed query reached downstream")
								})
								ch := middleware.NewChain([]middleware.Handler{edns.New(cfg), New(cfg), forbidden})
								w := mock.NewWriter(proto, addr)
								if wire {
									ch.ResetWire(w, request(t, q))
								} else {
									ch.Reset(w, q)
								}
								before := blocked.Value()
								ch.Next(context.Background())
								ch.Next(context.Background()) // cancellation prevents a second answer
								ch.Finish()
								if got := blocked.Value() - before; got != 1 {
									t.Fatalf("counter delta = %d, want 1", got)
								}
								got := w.Msg()
								if got == nil {
									t.Fatal("no reply")
								}
								raw, err := got.Pack()
								if err != nil {
									t.Fatal(err)
								}
								decoded := new(dns.Msg)
								if err := decoded.Unpack(raw); err != nil {
									t.Fatal(err)
								}
								if decoded.Id != 4321 || !decoded.Response || decoded.Opcode != dns.OpcodeQuery || decoded.Rcode != dns.RcodeSuccess ||
									decoded.Authoritative || decoded.AuthenticatedData || !decoded.RecursionAvailable ||
									decoded.RecursionDesired != rd || decoded.CheckingDisabled != cd {
									t.Fatalf("reply header = %+v", decoded.MsgHdr)
								}
								if !reflect.DeepEqual(decoded.Question, wantQuestion) || len(decoded.Answer) != 0 || len(decoded.Ns) != 0 {
									t.Fatalf("reply sections = %v / %v / %v", decoded.Question, decoded.Answer, decoded.Ns)
								}
								if optMode == "none" {
									if len(decoded.Extra) != 0 {
										t.Fatalf("non-EDNS Extra = %v", decoded.Extra)
									}
								} else {
									opt := decoded.IsEdns0()
									ede := dnsutil.GetEDE(decoded)
									if opt == nil || opt.Do() != (optMode == "do") || ede == nil ||
										ede.InfoCode != dns.ExtendedErrorCodeOther || ede.ExtraText != "AAAA response suppressed by policy" {
										t.Fatalf("OPT/EDE = %v / %v", opt, ede)
									}
								}
							})
						}
					}
				}
			}
		}
	}
}

func TestPassthrough(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*dns.Msg)
	}{
		{"A", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeA }},
		{"HTTPS", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeHTTPS }},
		{"SVCB", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeSVCB }},
		{"ANY", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypeANY }},
		{"PTR", func(q *dns.Msg) { q.Question[0].Qtype = dns.TypePTR }},
		{"CHAOS", func(q *dns.Msg) { q.Question[0].Qclass = dns.ClassCHAOS }},
		{"class ANY", func(q *dns.Msg) { q.Question[0].Qclass = dns.ClassANY }},
		{"STATUS", func(q *dns.Msg) { q.Opcode = dns.OpcodeStatus }},
		{"UPDATE", func(q *dns.Msg) { q.Opcode = dns.OpcodeUpdate }},
		{"response", func(q *dns.Msg) { q.Response = true }},
		{"no questions", func(q *dns.Msg) { q.Question = nil }},
		{"multiple questions", func(q *dns.Msg) { q.Question = append(q.Question, q.Question[0]) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := query(dns.TypeAAAA)
			tc.edit(q)
			calls := 0
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { calls++; ch.Cancel() })
			ch := middleware.NewChain([]middleware.Handler{New(&config.Config{BlockAAAA: true}), next})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch.Reset(w, q)
			before := blocked.Value()
			ch.Next(context.Background())
			if calls != 1 || w.Written() || blocked.Value() != before {
				t.Fatalf("calls=%d written=%v counter delta=%d", calls, w.Written(), blocked.Value()-before)
			}
		})
	}
}

func TestInternalAndDisabledPassthrough(t *testing.T) {
	for _, tc := range []struct {
		name, addr string
		ctx        context.Context
		disabled   bool
	}{
		{"internal writer", "127.0.0.255:0", context.Background(), false},
		{"internal context", "192.0.2.1:40000", middleware.MarkInternal(context.Background()), false},
		{"disabled", "192.0.2.1:40000", context.Background(), true},
	} {
		for _, wire := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wire=%v", tc.name, wire), func(t *testing.T) {
				next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
					if wire && !ch.Request.Undecoded() {
						t.Fatal("internal or disabled query decoded")
					}
					resp := new(dns.Msg)
					resp.SetReply(ch.Request.Msg())
					resp.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: "MiXeD.Example.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60}}}
					_ = ch.Writer.WriteMsg(resp)
					ch.Cancel()
				})
				b := New(&config.Config{BlockAAAA: !tc.disabled})
				ch := middleware.NewChain([]middleware.Handler{b, next})
				w := mock.NewWriter("udp", tc.addr)
				q := query(dns.TypeAAAA)
				if wire {
					ch.ResetWire(w, request(t, q))
				} else {
					ch.Reset(w, q)
				}
				before := blocked.Value()
				ch.Next(tc.ctx)
				ch.Finish()
				if !w.Written() || len(w.Msg().Answer) != 1 || blocked.Value() != before {
					t.Fatalf("internal/disabled answer = %v", w.Msg())
				}
			})
		}
	}
}

type errorWriter struct {
	*mock.Writer
	calls int
}

func (w *errorWriter) WriteMsg(*dns.Msg) error { w.calls++; return errors.New("write failed") }

func TestCounterSuccessfulWriteAndReplay(t *testing.T) {
	b := New(&config.Config{BlockAAAA: true})
	for _, replay := range []bool{false, true} {
		w := mock.NewWriter("udp", "192.0.2.1:40000")
		ch := middleware.NewChain([]middleware.Handler{b})
		ch.Reset(w, query(dns.TypeAAAA))
		if replay {
			ch.SetReplay()
		} else {
			ch.SetInlineOnly()
		}
		before := blocked.Value()
		ch.Next(context.Background())
		ch.Next(context.Background())
		if blocked.Value()-before != 1 || !w.Written() || ch.Handoff() {
			t.Fatalf("replay=%v counter delta=%d", replay, blocked.Value()-before)
		}
	}
	w := &errorWriter{Writer: mock.NewWriter("udp", "192.0.2.1:40000")}
	calls := 0
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { calls++; ch.Cancel() })
	ch := middleware.NewChain([]middleware.Handler{b, next})
	ch.Reset(w, query(dns.TypeAAAA))
	before := blocked.Value()
	ch.Next(context.Background())
	ch.Next(context.Background())
	if blocked.Value() != before || w.calls != 1 || calls != 0 {
		t.Fatalf("failed write: counter delta=%d writes=%d downstream=%d", blocked.Value()-before, w.calls, calls)
	}
}

func TestMalformedWire(t *testing.T) {
	q := query(dns.TypeAAAA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range [][]byte{nil, raw[:11], raw[:len(raw)-1]} {
		var r middleware.Request
		if r.ParseWire(packet, time.Time{}, nil) {
			t.Fatal("malformed packet accepted")
		}
	}
	r := request(t, q)
	// Simulate invalidation of borrowed transport bytes after parsing. A late
	// decode failure must cancel rather than answer unvalidated data.
	r.Raw()[12] = 255
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { t.Fatal("malformed request reached downstream") })
	ch := middleware.NewChain([]middleware.Handler{New(&config.Config{BlockAAAA: true}), next})
	ch.ResetWire(w, r)
	before := blocked.Value()
	ch.Next(context.Background())
	ch.Next(context.Background())
	if w.Written() || blocked.Value() != before {
		t.Fatal("malformed query answered or counted")
	}
}

func TestWirePassthroughAllocatesNothing(t *testing.T) {
	b := New(&config.Config{BlockAAAA: true})
	for _, tc := range []struct {
		name          string
		qtype, qclass uint16
	}{
		{"A", dns.TypeA, dns.ClassINET},
		{"HTTPS", dns.TypeHTTPS, dns.ClassINET},
		{"AAAA CHAOS", dns.TypeAAAA, dns.ClassCHAOS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := query(tc.qtype)
			q.Question[0].Qclass = tc.qclass
			raw, err := q.Pack()
			if err != nil {
				t.Fatal(err)
			}
			var req middleware.Request
			calls := 0
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				calls++
				if !ch.Request.Undecoded() {
					t.Fatal("nonmatching query decoded")
				}
				ch.Cancel()
			})
			ch := middleware.NewChain([]middleware.Handler{b, next})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ctx := middleware.WithResponseMeta(context.Background(), &ch.Meta)
			allocs := testing.AllocsPerRun(100, func() {
				if !req.ParseWire(raw, time.Time{}, nil) {
					t.Fatal("ParseWire rejected query")
				}
				ch.ResetWire(w, &req)
				ch.Next(ctx)
			})
			if allocs != 0 || calls != 101 {
				t.Fatalf("allocs=%v calls=%d, want 0 and 101", allocs, calls)
			}
		})
	}
}

// TestEDNSRejectionsPrecedeSuppression keeps protocol errors under the
// outer EDNS handler's control, rather than replacing them with NODATA.
func TestEDNSRejectionsPrecedeSuppression(t *testing.T) {
	for _, tc := range []struct {
		name  string
		edit  func(*dns.Msg)
		rcode int
	}{
		{"version", func(q *dns.Msg) { q.SetEdns0(1232, true); q.IsEdns0().SetVersion(1) }, dns.RcodeBadVers},
		{"duplicate OPT", func(q *dns.Msg) { q.SetEdns0(1232, false); q.Extra = append(q.Extra, q.Extra[0]) }, dns.RcodeFormatError},
		{"foreign OPT owner", func(q *dns.Msg) { q.SetEdns0(1232, false); q.IsEdns0().Hdr.Name = "other." }, dns.RcodeFormatError},
		{"malformed cookie", func(q *dns.Msg) {
			q.SetEdns0(1232, false)
			q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "01"}}
		}, dns.RcodeFormatError},
		{"opcode", func(q *dns.Msg) { q.Opcode = dns.OpcodeStatus }, dns.RcodeNotImplemented},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{BlockAAAA: true}
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { t.Fatal("protocol error reached downstream") })
			ch := middleware.NewChain([]middleware.Handler{edns.New(cfg), New(cfg), next})
			q := query(dns.TypeAAAA)
			tc.edit(q)
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch.Reset(w, q)
			before := blocked.Value()
			ch.Next(context.Background())
			if !w.Written() || w.Msg().Rcode != tc.rcode || blocked.Value() != before {
				t.Fatalf("reply=%v counter delta=%d, want rcode=%d and no suppression", w.Msg(), blocked.Value()-before, tc.rcode)
			}
		})
	}
}

// A generic writer may retain its reply after chain reuse; the lease path
// must decline it, leaving independently owned messages and questions.
func TestGenericWriterRetainsReplyAcrossReuse(t *testing.T) {
	b := New(&config.Config{BlockAAAA: true})
	ch := middleware.NewChain([]middleware.Handler{b})
	w := mock.NewWriter("udp", "192.0.2.1:40000")
	q := query(dns.TypeAAAA)
	ch.ResetWire(w, request(t, q))
	ch.Next(context.Background())
	first := w.Msg()
	firstWire, err := first.Pack()
	if err != nil {
		t.Fatal(err)
	}
	ch.Finish()
	q.SetQuestion("second.example.", dns.TypeAAAA)
	q.Id = 88
	ch.ResetWire(w, request(t, q))
	ch.Next(context.Background())
	ch.Finish()
	got, err := first.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, firstWire) {
		t.Fatal("retained reply changed on chain reuse")
	}
	if first == w.Msg() {
		t.Fatal("generic writer received reused reply storage")
	}
}

type refusingWireWriter struct {
	middleware.ResponseWriter
	lease           bool
	commitErr       error
	commits, aborts int
	storage         [512]byte
}

func (w *refusingWireWriter) WireReady() (middleware.WireCapability, bool) {
	return middleware.WireCapability{}, true
}
func (w *refusingWireWriter) WriteWire([]byte, middleware.WireInfo) error { return w.commitErr }
func (w *refusingWireWriter) BeginWire(size, reserve int) []byte {
	if !w.lease {
		return nil
	}
	return w.storage[: 0 : size+reserve]
}
func (w *refusingWireWriter) CommitWire(body []byte, info middleware.WireInfo) error {
	w.commits++
	return w.WriteWire(body, info)
}
func (w *refusingWireWriter) AbortWire() { w.aborts++ }

func TestWireLeaseAndCommitFallback(t *testing.T) {
	for _, tc := range []struct {
		name           string
		lease          bool
		err            error
		writes, aborts int
	}{
		{"no lease", false, nil, 0, 0},
		{"pre-write refusal", true, middleware.ErrWireFallback, 1, 1},
		{"transport error", true, errors.New("transport write failed"), 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := New(&config.Config{BlockAAAA: true})
			next := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) { t.Fatal("query reached downstream") })
			ch := middleware.NewChain([]middleware.Handler{b, next})
			w := mock.NewWriter("udp", "192.0.2.1:40000")
			ch.ResetWire(w, request(t, query(dns.TypeAAAA)))
			wrapper := &refusingWireWriter{ResponseWriter: ch.Writer, lease: tc.lease, commitErr: tc.err}
			ch.Writer = wrapper
			before := blocked.Value()
			ch.Next(context.Background())
			ch.Next(context.Background())
			ch.Finish()
			wantCount := int64(1)
			wantWritten := true
			if tc.name == "transport error" {
				wantCount, wantWritten = 0, false
			}
			if blocked.Value()-before != wantCount || w.Written() != wantWritten ||
				wrapper.commits != tc.writes || wrapper.aborts != tc.aborts {
				t.Fatalf("count=%d written=%v commits=%d aborts=%d", blocked.Value()-before, w.Written(), wrapper.commits, wrapper.aborts)
			}
		})
	}
}
