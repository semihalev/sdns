package cache

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

type recursionWorkErrorQueryer struct {
	err   error
	calls int
}

func (q *recursionWorkErrorQueryer) Query(context.Context, *dns.Msg) (*dns.Msg, error) {
	q.calls++
	return nil, q.err
}

func TestAdditionalAnswerRecursionWorkLimitEDE(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		rcode    int
		wantEDE  bool
		wantCode uint16
		wantText string
	}{
		{
			name: "typed work limit",
			err: &middleware.RecursionWorkLimitError{
				Kind:  middleware.RecursionWorkInternalQuery,
				Limit: 32,
			},
			rcode:    dns.RcodeServerFailure,
			wantEDE:  true,
			wantCode: middleware.RecursionWorkEDECode,
			wantText: middleware.RecursionWorkEDEText,
		},
		{
			name: "typed crypto work limit",
			err: &middleware.RecursionWorkLimitError{
				Kind:  middleware.RecursionWorkSignature,
				Limit: 32,
			},
			rcode:    dns.RcodeServerFailure,
			wantEDE:  true,
			wantCode: middleware.DNSSECWorkEDECode,
			wantText: middleware.DNSSECWorkEDEText,
		},
		{
			name:    "ordinary queryer error keeps original response",
			err:     errors.New("ordinary CNAME chase failure"),
			rcode:   dns.RcodeSuccess,
			wantEDE: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer c.Stop()

			queryer := &recursionWorkErrorQueryer{err: tt.err}
			c.SetQueryer(queryer)

			msg := new(dns.Msg)
			msg.SetQuestion("alias.example.", dns.TypeA)
			msg.SetEdns0(dnsutil.DefaultMsgSize, true)
			msg.Answer = []dns.RR{&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   "alias.example.",
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				Target: "target.example.",
			}}

			got := c.additionalAnswer(context.Background(), msg)
			if got.Rcode != tt.rcode {
				t.Fatalf("rcode = %s, want %s",
					dns.RcodeToString[got.Rcode], dns.RcodeToString[tt.rcode])
			}
			if queryer.calls != 1 {
				t.Fatalf("queryer calls = %d, want 1", queryer.calls)
			}

			ede := dnsutil.GetEDE(got)
			if !tt.wantEDE {
				if ede != nil {
					t.Fatalf("ordinary queryer error added EDE: %+v", ede)
				}
				return
			}
			if ede == nil {
				t.Fatal("work-limit SERVFAIL is missing EDE")
			}
			if ede.InfoCode != tt.wantCode {
				t.Errorf("EDE code = %d, want %d",
					ede.InfoCode, tt.wantCode)
			}
			if ede.ExtraText != tt.wantText {
				t.Errorf("EDE text = %q, want exact stable text %q",
					ede.ExtraText, tt.wantText)
			}
		})
	}
}

func TestRecursionWorkPolicySERVFAILCacheIsolation(t *testing.T) {
	tests := []struct {
		name       string
		mode       middleware.RecursionWorkMode
		kind       middleware.RecursionWorkKind
		edeCode    uint16
		extraText  string
		wantCode   uint16
		wantText   string
		wantCached bool
	}{
		{
			name:      "local enforce rejection is request scoped",
			mode:      middleware.RecursionWorkEnforce,
			kind:      middleware.RecursionWorkInternalQuery,
			edeCode:   middleware.RecursionWorkEDECode,
			extraText: middleware.RecursionWorkEDEText,
			wantCode:  middleware.RecursionWorkEDECode,
			wantText:  middleware.RecursionWorkEDEText,
		},
		{
			name:      "crypto rejection is EDE 5 and request scoped",
			mode:      middleware.RecursionWorkEnforce,
			kind:      middleware.RecursionWorkSignature,
			edeCode:   middleware.RecursionWorkEDECode,
			extraText: middleware.RecursionWorkEDEText,
			wantCode:  middleware.DNSSECWorkEDECode,
			wantText:  middleware.DNSSECWorkEDEText,
		},
		{
			name:       "upstream policy EDE remains cacheable in shadow",
			mode:       middleware.RecursionWorkShadow,
			kind:       middleware.RecursionWorkInternalQuery,
			edeCode:    dns.ExtendedErrorCodeUnableToConformToPolicy,
			extraText:  "upstream policy",
			wantCached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer c.Stop()

			ledger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
				Mode:               tt.mode,
				MaxOutboundQueries: 1,
				MaxInternalQueries: 1,
				MaxSignatureChecks: 1,
			})
			if err := ledger.Debit(tt.kind); err != nil {
				t.Fatalf("first work debit: %v", err)
			}
			secondErr := ledger.Debit(tt.kind)
			if tt.mode == middleware.RecursionWorkEnforce && !errors.Is(secondErr, middleware.ErrRecursionWorkLimit) {
				t.Fatalf("enforce crossing error = %v, want recursion work limit", secondErr)
			}
			if tt.mode == middleware.RecursionWorkShadow && secondErr != nil {
				t.Fatalf("shadow crossing error = %v, want nil", secondErr)
			}
			ctx := middleware.WithRecursionWork(context.Background(), ledger)
			if tt.mode == middleware.RecursionWorkEnforce {
				code, text := middleware.RecursionWorkEDE(ctx)
				if code != tt.wantCode || text != tt.wantText {
					t.Fatalf("latched EDE before cache = (%d, %q), want (%d, %q)",
						code, text, tt.wantCode, tt.wantText)
				}
			}

			req := new(dns.Msg)
			req.SetQuestion("policy-cache.example.", dns.TypeA)
			req.SetEdns0(dnsutil.DefaultMsgSize, true)
			res := dnsutil.SetRcodeWithEDE(
				req.Copy(),
				dns.RcodeServerFailure,
				true,
				tt.edeCode,
				tt.extraText,
			)
			if tt.mode == middleware.RecursionWorkEnforce {
				// Exercise the real wrapper's ability to recover EDNS from
				// the original request when a downstream SERVFAIL omitted it.
				res.Extra = nil
			}

			writer := mock.NewWriter("udp", "192.0.2.1:53000")
			rw := &ResponseWriter{
				ResponseWriter: writer,
				cache:          c,
				ctx:            ctx,
				req:            req,
			}
			if err := rw.WriteMsg(res); err != nil {
				t.Fatalf("WriteMsg: %v", err)
			}
			if !writer.Written() {
				t.Fatal("policy SERVFAIL was not written to the client")
			}
			if tt.mode == middleware.RecursionWorkEnforce {
				ede := dnsutil.GetEDE(writer.Msg())
				if ede == nil ||
					ede.InfoCode != tt.wantCode ||
					ede.ExtraText != tt.wantText {
					t.Fatalf("local policy EDE = %+v, want code=%d text=%q",
						ede, tt.wantCode, tt.wantText)
				}
				if writer.Msg().AuthenticatedData {
					t.Fatal("policy SERVFAIL retained AD=1")
				}
			}

			key := CacheKey{Question: req.Question[0], CD: false}.Hash()
			if _, cached := c.store.LookupByKey(key); cached {
				t.Fatal("policy SERVFAIL entered the ordinary answer cache")
			}
			hit, cached := c.store.LookupFailure(req, netip.Prefix{})
			if cached != tt.wantCached {
				t.Fatalf("failure-cache admission = %v, want %v", cached, tt.wantCached)
			}
			if !tt.wantCached {
				return
			}
			cachedResp := hit.Response(req)
			ede := dnsutil.GetEDE(cachedResp)
			if ede == nil || ede.InfoCode != dns.ExtendedErrorCodeCachedError {
				t.Fatalf("cached policy failure EDE = %+v, want EDE 13", ede)
			}
		})
	}
}

func TestRequestLocalFailureDoesNotPoisonIndependentRequest(t *testing.T) {
	tests := []struct {
		name             string
		setupA           func(*testing.T, dns.Question) (context.Context, error)
		ensureDownstream bool
		derivedDeadline  bool
		wantEDE          uint16
		checkEDE         bool
	}{
		{
			name: "work budget",
			setupA: func(t *testing.T, _ dns.Question) (context.Context, error) {
				t.Helper()
				ledger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
					Mode:               middleware.RecursionWorkEnforce,
					MaxOutboundQueries: 1,
					MaxInternalQueries: 32,
				})
				if err := ledger.Debit(middleware.RecursionWorkOutboundQuery); err != nil {
					t.Fatal(err)
				}
				if err := ledger.Debit(middleware.RecursionWorkOutboundQuery); !errors.Is(err, middleware.ErrRecursionWorkLimit) {
					t.Fatalf("second debit = %v, want ErrRecursionWorkLimit", err)
				}
				return middleware.WithRecursionWork(context.Background(), ledger), nil
			},
			wantEDE:  middleware.RecursionWorkEDECode,
			checkEDE: true,
		},
		{
			name: "resolution attempt limit",
			setupA: func(t *testing.T, q dns.Question) (context.Context, error) {
				t.Helper()
				ctx, guard := middleware.EnsureResolutionAttemptGuard(context.Background())
				for range 3 {
					if err := guard.Begin(q, "192.0.2.53:53", "udp"); err != nil {
						t.Fatal(err)
					}
				}
				err := guard.Begin(q, "192.0.2.53:53", "udp")
				if !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
					t.Fatalf("fourth attempt = %v, want ErrResolutionAttemptLimit", err)
				}
				return ctx, err
			},
		},
		{
			name: "best effort branch",
			setupA: func(_ *testing.T, _ dns.Question) (context.Context, error) {
				return middleware.WithBestEffortRecursionWork(context.Background()), nil
			},
		},
		{
			name: "derived request deadline",
			setupA: func(_ *testing.T, _ dns.Question) (context.Context, error) {
				return context.Background(), nil
			},
			ensureDownstream: true,
			derivedDeadline:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer c.Stop()

			q := dns.Question{
				Name:   "isolated-" + strings.ReplaceAll(tt.name, " ", "-") + ".example.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			ctxA, localErr := tt.setupA(t, q)
			fail := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
				markerCtx := ctx
				if tt.ensureDownstream {
					markerCtx, _ = middleware.EnsureResolutionAttemptGuard(markerCtx)
				}
				if tt.derivedDeadline {
					if ctx.Err() != nil {
						t.Fatalf("cache parent context unexpectedly canceled: %v", ctx.Err())
					}
					var cancel context.CancelFunc
					markerCtx, cancel = context.WithDeadline(markerCtx, time.Time{})
					defer cancel()
					localErr = markerCtx.Err()
				}
				resp := new(dns.Msg)
				resp.SetRcode(ch.Request, dns.RcodeServerFailure)
				middleware.MarkRequestLocalFailureResponse(markerCtx, resp, localErr)
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
			})
			reqA := new(dns.Msg)
			reqA.SetQuestion(q.Name, q.Qtype)
			reqA.SetEdns0(dnsutil.DefaultMsgSize, true)
			writerA := mock.NewWriter("udp", "192.0.2.1:53000")
			chainA := middleware.NewChain([]middleware.Handler{c, fail})
			chainA.Reset(writerA, reqA)
			chainA.Next(ctxA)

			if got := writerA.Msg(); got == nil || got.Rcode != dns.RcodeServerFailure {
				t.Fatalf("client A response = %#v, want SERVFAIL", got)
			} else if tt.checkEDE {
				ede := dnsutil.GetEDE(got)
				if ede == nil || ede.InfoCode != tt.wantEDE {
					t.Fatalf("client A EDE = %+v, want code %d", ede, tt.wantEDE)
				}
			}
			if hit, cached := c.store.LookupFailure(reqA, netip.Prefix{}); cached {
				t.Fatalf("request-local client A failure entered shared cache: %#v", hit)
			}

			cleanLedger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
				Mode:               middleware.RecursionWorkEnforce,
				MaxOutboundQueries: 32,
				MaxInternalQueries: 32,
			})
			ctxB := middleware.WithRecursionWork(context.Background(), cleanLedger)
			downstreamCalls := 0
			success := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				downstreamCalls++
				resp := new(dns.Msg)
				resp.SetReply(ch.Request)
				resp.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   []byte{192, 0, 2, 80},
				}}
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
			})
			reqB := new(dns.Msg)
			reqB.SetQuestion(q.Name, q.Qtype)
			reqB.SetEdns0(dnsutil.DefaultMsgSize, true)
			writerB := mock.NewWriter("udp", "192.0.2.2:53000")
			chainB := middleware.NewChain([]middleware.Handler{c, success})
			chainB.Reset(writerB, reqB)
			chainB.Next(ctxB)

			if downstreamCalls != 1 {
				t.Fatalf("client B downstream calls = %d, want 1", downstreamCalls)
			}
			if got := writerB.Msg(); got == nil || got.Rcode != dns.RcodeSuccess {
				t.Fatalf("client B response = %#v, want independent success", got)
			}
			snapshot := cleanLedger.Snapshot()
			if snapshot.OutboundQueries != 0 || snapshot.InternalQueries != 0 || cleanLedger.EnforcementError() != nil {
				t.Fatalf("client B clean ledger changed: %+v error=%v", snapshot, cleanLedger.EnforcementError())
			}
		})
	}
}

func TestCNAMEChaseRequestLocalFailureDoesNotEnterFailureCache(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(*testing.T, dns.Question) (context.Context, error)
		wantCode uint16
	}{
		{
			name: "work budget",
			setup: func(t *testing.T, _ dns.Question) (context.Context, error) {
				t.Helper()
				ledger := middleware.NewRecursionWorkLedger(middleware.RecursionWorkPolicy{
					Mode:               middleware.RecursionWorkEnforce,
					MaxOutboundQueries: 1,
					MaxInternalQueries: 32,
				})
				if err := ledger.Debit(middleware.RecursionWorkOutboundQuery); err != nil {
					t.Fatal(err)
				}
				err := ledger.Debit(middleware.RecursionWorkOutboundQuery)
				if !errors.Is(err, middleware.ErrRecursionWorkLimit) {
					t.Fatalf("second debit = %v, want ErrRecursionWorkLimit", err)
				}
				return middleware.WithRecursionWork(context.Background(), ledger), err
			},
			wantCode: middleware.RecursionWorkEDECode,
		},
		{
			name: "resolution attempt limit",
			setup: func(t *testing.T, q dns.Question) (context.Context, error) {
				t.Helper()
				ctx, guard := middleware.EnsureResolutionAttemptGuard(context.Background())
				for range 3 {
					if err := guard.Begin(q, "192.0.2.53:53", "udp"); err != nil {
						t.Fatal(err)
					}
				}
				err := guard.Begin(q, "192.0.2.53:53", "udp")
				if !errors.Is(err, middleware.ErrResolutionAttemptLimit) {
					t.Fatalf("fourth attempt = %v, want ErrResolutionAttemptLimit", err)
				}
				return ctx, err
			},
			wantCode: dns.ExtendedErrorCodeOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New(&config.Config{CacheSize: 1024, Expire: 300})
			defer c.Stop()

			q := dns.Question{
				Name:   "alias-" + strings.ReplaceAll(tt.name, " ", "-") + ".example.",
				Qtype:  dns.TypeA,
				Qclass: dns.ClassINET,
			}
			ctx, localErr := tt.setup(t, q)
			c.SetQueryer(&recursionWorkErrorQueryer{err: localErr})

			outer := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
				resp := new(dns.Msg)
				resp.SetReply(ch.Request)
				resp.SetEdns0(dnsutil.DefaultMsgSize, true)
				resp.Answer = []dns.RR{&dns.CNAME{
					Hdr: dns.RR_Header{
						Name:   q.Name,
						Rrtype: dns.TypeCNAME,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					Target: "target.example.",
				}}
				_ = ch.Writer.WriteMsg(resp)
				ch.Cancel()
			})

			req := new(dns.Msg)
			req.SetQuestion(q.Name, q.Qtype)
			req.SetEdns0(dnsutil.DefaultMsgSize, true)
			writer := mock.NewWriter("udp", "192.0.2.1:53000")
			chain := middleware.NewChain([]middleware.Handler{c, outer})
			chain.Reset(writer, req)
			chain.Next(ctx)

			got := writer.Msg()
			if got == nil || got.Rcode != dns.RcodeServerFailure {
				t.Fatalf("CNAME chase response = %#v, want SERVFAIL", got)
			}
			ede := dnsutil.GetEDE(got)
			if ede == nil || ede.InfoCode != tt.wantCode {
				t.Fatalf("CNAME chase EDE = %+v, want code %d", ede, tt.wantCode)
			}
			if hit, cached := c.store.LookupFailure(req, netip.Prefix{}); cached {
				t.Fatalf("CNAME request-local failure entered shared cache: %#v", hit)
			}
		})
	}
}

func TestCNAMEChaseSharedFailureEntersFailureCache(t *testing.T) {
	c := New(&config.Config{CacheSize: 1024, Expire: 300})
	defer c.Stop()

	req := new(dns.Msg)
	req.SetQuestion("loop.example.", dns.TypeA)
	outer := middleware.HandlerFunc(func(_ context.Context, ch *middleware.Chain) {
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		resp.Answer = []dns.RR{&dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   ch.Request.Question[0].Name,
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			Target: ch.Request.Question[0].Name,
		}}
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})

	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	chain := middleware.NewChain([]middleware.Handler{c, outer})
	chain.Reset(writer, req)
	chain.Next(context.Background())

	if got := writer.Msg(); got == nil || got.Rcode != dns.RcodeServerFailure {
		t.Fatalf("CNAME loop response = %#v, want SERVFAIL", got)
	}
	hit, cached := c.store.LookupFailure(req, netip.Prefix{})
	if !cached {
		t.Fatal("shared CNAME resolution failure missing from RFC 9520 cache")
	}
	if hit.Provenance != FailureProvenance("response") {
		t.Fatalf("shared CNAME failure provenance = %q, want response", hit.Provenance)
	}
}
