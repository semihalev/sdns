package middleware

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/contextutil"
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
		{name: "failure probe limit", err: ErrFailureProbeLimit},
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
	ch.Request = NewRequest(new(dns.Msg))
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

// TestEnsureResolutionAttemptGuardPinsOnDeadlineCarrier pins the anchoring
// contract on the ordinary request path: the guard lands in the deadline
// carrier's request-lifetime slot, so establishing and re-establishing it
// derives no context, and every sub-query sees the same guard.
func TestEnsureResolutionAttemptGuardPinsOnDeadlineCarrier(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	meta := new(ResponseMeta)
	ctx := WithResponseMeta(lazy, meta)

	got, guard := EnsureResolutionAttemptGuard(ctx)
	if guard == nil {
		t.Fatal("no guard established")
	}
	if got != ctx {
		t.Fatal("anchoring the guard on a deadline-carried request derived a context")
	}
	if meta.ResolutionAttemptGuard() != guard {
		t.Fatal("guard is not the request meta's guard")
	}

	again, guard2 := EnsureResolutionAttemptGuard(got)
	if again != got || guard2 != guard {
		t.Fatal("re-establishing the guard was not the identity")
	}
	if ResolutionAttemptGuardFrom(got) != guard {
		t.Fatal("guard not readable back through the pin")
	}

	// The anchor must survive meta reuse: a reader holding only the context
	// still sees the original guard after the pooled meta was reset.
	meta.Reset()
	if ResolutionAttemptGuardFrom(got) != guard {
		t.Fatal("guard lost after the originating ResponseMeta was reset")
	}
}

func TestEnsureResolutionAttemptGuardForeignContextFallsBack(t *testing.T) {
	meta := new(ResponseMeta)
	ctx := WithResponseMeta(context.Background(), meta)

	got, guard := EnsureResolutionAttemptGuard(ctx)
	if guard == nil {
		t.Fatal("no guard established")
	}
	if got == ctx {
		t.Fatal("a foreign context cannot anchor without deriving a value node")
	}
	if ResolutionAttemptGuardFrom(got) != guard {
		t.Fatal("guard not readable from the derived context")
	}

	again, guard2 := EnsureResolutionAttemptGuard(got)
	if again != got || guard2 != guard {
		t.Fatal("re-establishing on the derived context was not the identity")
	}
}

// TestResolutionAttemptGuardShadowingWinsOverPin pins the anchor precedence:
// a derived value node must shadow the request's pinned guard for its
// subtree, exactly as it did when every anchor was a value node — otherwise
// custom or forked flows would account retries against the wrong guard.
func TestResolutionAttemptGuardShadowingWinsOverPin(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	ctx, first := EnsureResolutionAttemptGuard(WithResponseMeta(lazy, new(ResponseMeta)))

	second := new(ResponseMeta).EnsureResolutionAttemptGuard()
	if second == first {
		t.Fatal("fixture guards must differ")
	}
	shadowed := WithResolutionAttemptGuard(ctx, second)
	if shadowed == ctx {
		t.Fatal("anchoring a different guard over the pin must derive a context")
	}
	if got := ResolutionAttemptGuardFrom(shadowed); got != second {
		t.Fatalf("subtree sees the pinned guard instead of its shadowing anchor")
	}
	if got := ResolutionAttemptGuardFrom(ctx); got != first {
		t.Fatal("the outer context lost its pinned guard")
	}

	// Shadowing back to the pinned guard inside the subtree works too.
	back := WithResolutionAttemptGuard(shadowed, first)
	if got := ResolutionAttemptGuardFrom(back); got != first {
		t.Fatal("re-shadowing the pinned guard was hidden")
	}
}

// TestGuardOverrideStaysOnItsSubtree pins the P1 review finding: overriding
// a value- or fork-anchored guard while the shared carrier has no guard pin
// must scope the override to the target subtree. Pinning it instead hands
// the override to the base and sibling contexts — RFC 9520 attempt
// accounting split across scopes — while the target keeps its old guard.
func TestGuardOverrideStaysOnItsSubtree(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	base := WithResponseMeta(lazy, new(ResponseMeta))

	// The forked cut exposes the host guard through its own Value hook; the
	// carrier's pin table stays guard-free.
	forked, meta := WithForkedCut(base)
	if meta == nil {
		t.Fatal("no meta to fork")
	}
	hostGuard := ResolutionAttemptGuardFrom(forked)
	if hostGuard == nil {
		t.Fatal("forked cut carries no guard")
	}

	override := new(ResponseMeta).EnsureResolutionAttemptGuard()
	overridden := WithResolutionAttemptGuard(forked, override)
	if got := ResolutionAttemptGuardFrom(overridden); got != override {
		t.Fatal("the target subtree did not receive its override")
	}
	if got := ResolutionAttemptGuardFrom(forked); got != hostGuard {
		t.Fatal("the forked context lost its own guard")
	}
	if got := ResolutionAttemptGuardFrom(base); got != hostGuard {
		t.Fatal("the override leaked through the shared carrier to the base context")
	}
}

// TestWithForkedCutHonorsAnchoredGuards pins that a forked cut selects the
// anchored guard through the same helper as every other consumer: the pin on
// the ordinary path, and a shadowing value node when one is nearer.
func TestWithForkedCutHonorsAnchoredGuards(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	ctx, guard := EnsureResolutionAttemptGuard(WithResponseMeta(lazy, new(ResponseMeta)))

	forked, meta := WithForkedCut(ctx)
	if meta == nil {
		t.Fatal("no meta to fork")
	}
	if got := ResolutionAttemptGuardFrom(forked); got != guard {
		t.Fatal("forked cut did not adopt the pinned guard")
	}

	shadow := new(ResponseMeta).EnsureResolutionAttemptGuard()
	forkedShadow, _ := WithForkedCut(WithResolutionAttemptGuard(ctx, shadow))
	if got := ResolutionAttemptGuardFrom(forkedShadow); got != shadow {
		t.Fatal("forked cut ignored the nearest shadowing anchor")
	}
}

func TestEnsureResolutionAttemptGuardReestablishAllocsNothing(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	ctx, guard := EnsureResolutionAttemptGuard(WithResponseMeta(lazy, new(ResponseMeta)))

	allocs := testing.AllocsPerRun(100, func() {
		got, g := EnsureResolutionAttemptGuard(ctx)
		if got != ctx || g != guard {
			t.Fatal("re-establish diverged")
		}
	})
	if allocs != 0 {
		t.Fatalf("re-establishing the pinned guard allocated %.0f times, want 0", allocs)
	}
}
