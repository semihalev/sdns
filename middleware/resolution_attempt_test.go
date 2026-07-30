package middleware

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

func TestResolutionAttemptGuardCanonicalTupleLimit(t *testing.T) {
	t.Parallel()

	guard := NewResolutionAttemptGuard()
	q := dns.Question{Name: "WWW.Example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	endpoints := []string{
		"[2001:db8::1]:53",
		"[2001:0db8:0:0:0:0:0:1]:53",
		"[2001:DB8::1]:53",
	}

	for i, endpoint := range endpoints {
		if err := guard.Begin(q, endpoint, "UDP"); err != nil {
			t.Fatalf("attempt %d = %v, want allowed", i+1, err)
		}
		q.Name = "www.example"
	}

	err := guard.Begin(q, endpoints[0], "udp")
	if !errors.Is(err, ErrResolutionAttemptLimit) {
		t.Fatalf("fourth canonical tuple attempt = %v, want ErrResolutionAttemptLimit", err)
	}
	var limitErr *ResolutionAttemptLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("fourth attempt type = %T, want *ResolutionAttemptLimitError", err)
	}
	if limitErr.Endpoint != "[2001:db8::1]:53" || limitErr.Transport != "udp" {
		t.Fatalf("limit tuple = %s/%s, want canonical endpoint/transport", limitErr.Endpoint, limitErr.Transport)
	}
}

func TestResolutionAttemptGuardTupleDimensionsAreIndependent(t *testing.T) {
	t.Parallel()

	guard := NewResolutionAttemptGuard()
	base := dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for range maxResolutionAttempts {
		if err := guard.Begin(base, "192.0.2.1:53", "udp"); err != nil {
			t.Fatal(err)
		}
	}

	tests := []struct {
		name      string
		question  dns.Question
		endpoint  string
		transport string
	}{
		{name: "qname", question: dns.Question{Name: "other.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, endpoint: "192.0.2.1:53", transport: "udp"},
		{name: "qtype", question: dns.Question{Name: base.Name, Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}, endpoint: "192.0.2.1:53", transport: "udp"},
		{name: "qclass", question: dns.Question{Name: base.Name, Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}, endpoint: "192.0.2.1:53", transport: "udp"},
		{name: "endpoint", question: base, endpoint: "192.0.2.2:53", transport: "udp"},
		{name: "transport", question: base, endpoint: "192.0.2.1:53", transport: "tcp"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if err := guard.Begin(tt.question, tt.endpoint, tt.transport); err != nil {
				t.Fatalf("independent tuple rejected: %v", err)
			}
		})
	}
}

func TestResolutionAttemptGuardConcurrentLimit(t *testing.T) {
	t.Parallel()

	guard := NewResolutionAttemptGuard()
	q := dns.Question{Name: "concurrent.example.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET}
	var accepted atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup

	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := guard.Begin(q, "192.0.2.10:53", "tcp")
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrResolutionAttemptLimit):
				rejected.Add(1)
			default:
				t.Errorf("unexpected Begin error: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := accepted.Load(); got != maxResolutionAttempts {
		t.Fatalf("accepted = %d, want %d", got, maxResolutionAttempts)
	}
	if got := rejected.Load(); got != 64-maxResolutionAttempts {
		t.Fatalf("rejected = %d, want %d", got, 64-maxResolutionAttempts)
	}
}

func TestResolutionAttemptGuardResponseMetaOwnershipAndReset(t *testing.T) {
	t.Parallel()

	var meta ResponseMeta
	ctx := WithResponseMeta(context.Background(), &meta)
	ctx, first := EnsureResolutionAttemptGuard(ctx)
	if first == nil || ResolutionAttemptGuardFrom(ctx) != first {
		t.Fatal("EnsureResolutionAttemptGuard did not pin the ResponseMeta guard")
	}

	q := dns.Question{Name: "reset.example.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for range maxResolutionAttempts {
		if err := BeginResolutionAttempt(ctx, q, "192.0.2.20:53", "udp"); err != nil {
			t.Fatal(err)
		}
	}

	meta.Reset()
	freshCtx, second := EnsureResolutionAttemptGuard(WithResponseMeta(context.Background(), &meta))
	if second == nil || second == first {
		t.Fatal("ResponseMeta Reset reused the previous request-tree guard")
	}
	if err := BeginResolutionAttempt(freshCtx, q, "192.0.2.20:53", "udp"); err != nil {
		t.Fatalf("fresh request attempt rejected: %v", err)
	}
	limitErr := BeginResolutionAttempt(ctx, q, "192.0.2.20:53", "udp")
	if !errors.Is(limitErr, ErrResolutionAttemptLimit) {
		t.Fatalf("detached pinned guard after Reset = %v, want original exhaustion", limitErr)
	}
	marked := new(dns.Msg)
	marked.SetQuestion(q.Name, q.Qtype)
	other := marked.Copy()
	MarkRequestLocalFailureResponse(ctx, marked, limitErr)
	if got := RequestLocalFailureForResponse(ctx, marked); !errors.Is(got, ErrResolutionAttemptLimit) {
		t.Fatalf("marked response provenance = %v, want ErrResolutionAttemptLimit", got)
	}
	if got := RequestLocalFailureForResponse(ctx, other); got != nil {
		t.Fatalf("copied response inherited pointer provenance: %v", got)
	}
	if got := RequestLocalFailureForResponse(freshCtx, marked); got != nil {
		t.Fatalf("fresh request inherited previous response provenance: %v", got)
	}
}

func TestRequestLocalFailureResponseIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "work limit", err: ErrRecursionWorkLimit},
		{name: "attempt limit", err: ErrResolutionAttemptLimit},
		{name: "queryer recursion", err: ErrMaxRecursion},
		{name: "canceled", err: context.Canceled},
		{name: "deadline", err: context.DeadlineExceeded},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx, _ := EnsureResolutionAttemptGuard(context.Background())
			marked := new(dns.Msg)
			marked.SetQuestion("local.example.", dns.TypeA)
			MarkRequestLocalFailureResponse(ctx, marked, tt.err)

			if got := RequestLocalFailureForResponse(ctx, marked); !errors.Is(got, tt.err) {
				t.Fatalf("exact response provenance = %v, want %v", got, tt.err)
			}
			if got := RequestLocalFailureForResponse(ctx, marked.Copy()); got != nil {
				t.Fatalf("copied response inherited request-local provenance: %v", got)
			}

			unmarked := new(dns.Msg)
			unmarked.SetQuestion("local.example.", dns.TypeA)
			MarkRequestLocalFailureResponse(ctx, unmarked, errors.New("upstream failure"))
			if got := RequestLocalFailureForResponse(ctx, unmarked); got != nil {
				t.Fatalf("shared upstream failure was marked request-local: %v", got)
			}
		})
	}
}

func TestChainResponseMetaOwnsResolutionAttemptGuardWhenNeeded(t *testing.T) {
	t.Parallel()

	var got *ResolutionAttemptGuard
	ch := NewChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		meta := ResponseMetaFrom(ctx)
		ctx, got = EnsureResolutionAttemptGuard(ctx)
		if meta == nil || got == nil || meta.ResolutionAttemptGuard() != got ||
			ResolutionAttemptGuardFrom(ctx) != got {
			t.Error("chain ResponseMeta did not own and pin the lazy RFC 9520 guard")
		}
		ch.Cancel()
	})})
	ch.Request = new(dns.Msg)
	ch.Next(context.Background())

	if got == nil {
		t.Fatal("guard was not established with recursion firewall disabled")
	}
}

func TestCanonicalResolutionEndpoint(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"192.0.2.1:053":                            "192.0.2.1:53",
		"[2001:0DB8:0:0::1]:53":                    "[2001:db8::1]:53",
		"DNS.Example.COM.:0053":                    "dns.example.com:53",
		"HTTPS://DNS.Example.COM.:443/dns-query#x": "https://dns.example.com/dns-query",
	}
	for input, want := range tests {
		if got := CanonicalResolutionEndpoint(input); got != want {
			t.Errorf("CanonicalResolutionEndpoint(%q) = %q, want %q", input, got, want)
		}
	}
}
