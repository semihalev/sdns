package cache

import (
	"context"
	"errors"
	"testing"

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
			name:       "local enforce rejection is request scoped",
			mode:       middleware.RecursionWorkEnforce,
			kind:       middleware.RecursionWorkInternalQuery,
			edeCode:    middleware.RecursionWorkEDECode,
			extraText:  middleware.RecursionWorkEDEText,
			wantCode:   middleware.RecursionWorkEDECode,
			wantText:   middleware.RecursionWorkEDEText,
			wantCached: false,
		},
		{
			name:       "crypto rejection is EDE 5 and request scoped",
			mode:       middleware.RecursionWorkEnforce,
			kind:       middleware.RecursionWorkSignature,
			edeCode:    middleware.RecursionWorkEDECode,
			extraText:  middleware.RecursionWorkEDEText,
			wantCode:   middleware.DNSSECWorkEDECode,
			wantText:   middleware.DNSSECWorkEDEText,
			wantCached: false,
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
			_, cached := c.store.LookupByKey(key)
			if cached != tt.wantCached {
				t.Fatalf("policy SERVFAIL cached = %v, want %v", cached, tt.wantCached)
			}
		})
	}
}
