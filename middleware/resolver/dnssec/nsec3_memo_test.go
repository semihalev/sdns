package dnssec

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/contextutil"
)

var errNSEC3MemoTestWork = errors.New("test NSEC3 memo work failure")

type nsec3MemoTestWork struct {
	access   NSEC3HashMemoAccess
	calls    atomic.Uint32
	failOnce atomic.Bool
	entered  chan struct{}
	unblock  <-chan struct{}
	once     sync.Once
}

func (w *nsec3MemoTestWork) BeginNSEC3Hash() (func(), error) {
	call := w.calls.Add(1)
	if w.entered != nil {
		w.once.Do(func() { close(w.entered) })
		<-w.unblock
	}
	if w.failOnce.Load() && call == 1 {
		return nil, errNSEC3MemoTestWork
	}
	return func() {}, nil
}

func (w *nsec3MemoTestWork) NSEC3HashMemos() NSEC3HashMemoAccess {
	return w.access
}

func hashNSEC3MemoTestName(
	name string,
	parameters aggressiveNSEC3Parameters,
	work NSEC3Work,
) ([]byte, error) {
	return hashNSEC3MemoTestNameForRing(name, "", 0, parameters, work)
}

func hashNSEC3MemoTestNameForRing(
	name string,
	zoneName string,
	qclass uint16,
	parameters aggressiveNSEC3Parameters,
	work NSEC3Work,
) ([]byte, error) {
	canonical, err := newAggressiveCanonicalName(name)
	if err != nil {
		return nil, err
	}
	var zone aggressiveCanonicalName
	if zoneName != "" {
		zone, err = newAggressiveCanonicalName(zoneName)
		if err != nil {
			return nil, err
		}
	}
	hasher := aggressiveNSEC3Hasher{
		parameters: parameters,
		zone:       zone,
		qclass:     qclass,
		work:       work,
		hashes:     make(map[string][]byte),
	}
	return hasher.hash(canonical)
}

func TestNSEC3HashMemoRequiredDeduplicatesRepeatedAndConcurrentHashes(t *testing.T) {
	parameters := aggressiveNSEC3Parameters{
		hash: dns.SHA1,
		salt: []byte{0x01, 0x23, 0x45},
	}

	t.Run("repeated", func(t *testing.T) {
		memo := NewNSEC3HashMemo()
		work := &nsec3MemoTestWork{
			access: NSEC3HashMemoAccess{Read: memo, Write: memo},
		}

		first, err := hashNSEC3MemoTestName("www.example.", parameters, work)
		if err != nil {
			t.Fatalf("first hash: %v", err)
		}
		second, err := hashNSEC3MemoTestName("www.example.", parameters, work)
		if err != nil {
			t.Fatalf("second hash: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("repeated hash mismatch: %x != %x", first, second)
		}
		if got := work.calls.Load(); got != 1 {
			t.Fatalf("required hash debits = %d, want 1", got)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		memo := NewNSEC3HashMemo()
		entered := make(chan struct{})
		unblock := make(chan struct{})
		work := &nsec3MemoTestWork{
			access:  NSEC3HashMemoAccess{Read: memo, Write: memo},
			entered: entered,
			unblock: unblock,
		}

		type result struct {
			value []byte
			err   error
		}
		const followers = 31
		results := make(chan result, followers+1)

		go func() {
			value, err := hashNSEC3MemoTestName("parallel.example.", parameters, work)
			results <- result{value: value, err: err}
		}()
		<-entered

		start := make(chan struct{})
		var ready sync.WaitGroup
		ready.Add(followers)
		for range followers {
			go func() {
				ready.Done()
				<-start
				value, err := hashNSEC3MemoTestName("parallel.example.", parameters, work)
				results <- result{value: value, err: err}
			}()
		}
		ready.Wait()
		close(start)
		close(unblock)

		var want []byte
		for range followers + 1 {
			got := <-results
			if got.err != nil {
				t.Fatalf("concurrent hash: %v", got.err)
			}
			if want == nil {
				want = got.value
				continue
			}
			if !bytes.Equal(got.value, want) {
				t.Fatalf("concurrent hash mismatch: %x != %x", got.value, want)
			}
		}
		if got := work.calls.Load(); got != 1 {
			t.Fatalf("concurrent required hash debits = %d, want 1", got)
		}
	})
}

func TestInheritNSEC3HashMemosCarriesEveryLaneOnly(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	parent = EnsureNSEC3HashMemo(parent)
	cancel()

	child := InheritNSEC3HashMemos(context.Background(), parent)
	if child.Err() != nil {
		t.Fatalf("memo inheritance copied parent cancellation: %v", child.Err())
	}
	for _, scope := range []NSEC3HashMemoScope{
		NSEC3HashMemoScopeRequired,
		NSEC3HashMemoScopeResolverOptional,
		NSEC3HashMemoScopeCacheOptional,
	} {
		if got, want := NSEC3HashMemoFromContextScope(child, scope),
			NSEC3HashMemoFromContextScope(parent, scope); got == nil || got != want {
			t.Fatalf("scope %d inherited memo = %p, want %p", scope, got, want)
		}
	}
}

func TestNSEC3HashMemoDirectionalRequiredAndOptionalAccess(t *testing.T) {
	parameters := aggressiveNSEC3Parameters{hash: dns.SHA1}

	t.Run("optional reads value paid by required work", func(t *testing.T) {
		requiredMemo := NewNSEC3HashMemo()
		required := &nsec3MemoTestWork{
			access: NSEC3HashMemoAccess{
				Read:  requiredMemo,
				Write: requiredMemo,
			},
		}
		optional := &nsec3MemoTestWork{
			access: NSEC3HashMemoAccess{
				Read:  requiredMemo,
				Write: NewNSEC3HashMemo(),
			},
		}

		requiredValue, err := hashNSEC3MemoTestName("direction.example.", parameters, required)
		if err != nil {
			t.Fatalf("required hash: %v", err)
		}
		optionalValue, err := hashNSEC3MemoTestName("direction.example.", parameters, optional)
		if err != nil {
			t.Fatalf("optional hash: %v", err)
		}
		if !bytes.Equal(requiredValue, optionalValue) {
			t.Fatalf("required/optional hash mismatch: %x != %x", requiredValue, optionalValue)
		}
		if got := required.calls.Load(); got != 1 {
			t.Fatalf("required hash debits = %d, want 1", got)
		}
		if got := optional.calls.Load(); got != 0 {
			t.Fatalf("optional reread debits = %d, want 0", got)
		}
	})

	t.Run("optional write cannot bypass later required debit", func(t *testing.T) {
		requiredMemo := NewNSEC3HashMemo()
		required := &nsec3MemoTestWork{
			access: NSEC3HashMemoAccess{
				Read:  requiredMemo,
				Write: requiredMemo,
			},
		}
		optional := &nsec3MemoTestWork{
			access: NSEC3HashMemoAccess{
				Read:  requiredMemo,
				Write: NewNSEC3HashMemo(),
			},
		}

		optionalValue, err := hashNSEC3MemoTestName("direction.example.", parameters, optional)
		if err != nil {
			t.Fatalf("optional hash: %v", err)
		}
		if got := optional.calls.Load(); got != 1 {
			t.Fatalf("optional hash debits = %d, want 1", got)
		}

		requiredValue, err := hashNSEC3MemoTestName("direction.example.", parameters, required)
		if err != nil {
			t.Fatalf("required hash after optional: %v", err)
		}
		if !bytes.Equal(optionalValue, requiredValue) {
			t.Fatalf("optional/required hash mismatch: %x != %x", optionalValue, requiredValue)
		}
		if got := required.calls.Load(); got != 1 {
			t.Fatalf("required hash debits after optional write = %d, want 1", got)
		}
	})
}

func TestNSEC3HashMemoRequiredVerifierFeedsOptionalEvaluator(t *testing.T) {
	const qname = "a.b.c.work-factor.example."
	records := newWorkFactorNSEC3ProofRecords(0, 4)
	msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	shared := NewNSEC3HashMemo()
	required := &nsec3MemoTestWork{
		access: NSEC3HashMemoAccess{Read: shared, Write: shared},
	}
	secure, err := VerifyNameErrorForZoneWithWork(
		msg,
		records,
		workFactorZone,
		required,
	)
	if err != nil || !secure {
		t.Fatalf("required verifier = secure:%v err:%v, want secure", secure, err)
	}

	optional := &nsec3MemoTestWork{
		access: NSEC3HashMemoAccess{
			Read:  shared,
			Write: NewNSEC3HashMemo(),
		},
	}
	result, err := EvaluateAggressiveNSEC3(
		msg.Question[0],
		workFactorZone,
		records,
		optional,
	)
	if err != nil || result.Rcode != dns.RcodeNameError {
		t.Fatalf("optional evaluator = rcode:%d err:%v, want NXDOMAIN", result.Rcode, err)
	}
	if got := optional.calls.Load(); got != 0 {
		t.Fatalf("optional evaluator repeated %d required hashes, want 0", got)
	}
	if got := required.calls.Load(); got != 5 {
		t.Fatalf("required unique hashes = %d, want 5", got)
	}
}

func TestNSEC3HashMemoDoesNotCacheFailures(t *testing.T) {
	memo := NewNSEC3HashMemo()
	work := &nsec3MemoTestWork{
		access: NSEC3HashMemoAccess{Read: memo, Write: memo},
	}
	work.failOnce.Store(true)
	parameters := aggressiveNSEC3Parameters{hash: dns.SHA1}

	if _, err := hashNSEC3MemoTestName("retry.example.", parameters, work); !errors.Is(err, errNSEC3MemoTestWork) {
		t.Fatalf("first hash error = %v, want %v", err, errNSEC3MemoTestWork)
	}
	firstSuccess, err := hashNSEC3MemoTestName("retry.example.", parameters, work)
	if err != nil {
		t.Fatalf("retry hash: %v", err)
	}
	secondSuccess, err := hashNSEC3MemoTestName("retry.example.", parameters, work)
	if err != nil {
		t.Fatalf("memoized retry hash: %v", err)
	}
	if !bytes.Equal(firstSuccess, secondSuccess) {
		t.Fatalf("retry hash mismatch: %x != %x", firstSuccess, secondSuccess)
	}
	if got := work.calls.Load(); got != 2 {
		t.Fatalf("hash debits after transient failure and retry = %d, want 2", got)
	}
}

func TestNSEC3HashMemoCanonicalNamesCoalesceAndTupleChangesPartition(t *testing.T) {
	memo := NewNSEC3HashMemo()
	work := &nsec3MemoTestWork{
		access: NSEC3HashMemoAccess{Read: memo, Write: memo},
	}
	base := aggressiveNSEC3Parameters{
		hash:       dns.SHA1,
		iterations: 1,
		salt:       []byte{0x01, 0x23},
	}

	plain, err := hashNSEC3MemoTestName("WWW.Example.", base, work)
	if err != nil {
		t.Fatalf("mixed-case hash: %v", err)
	}
	escaped, err := hashNSEC3MemoTestName(
		`\087\087\087.\069xample.`,
		base,
		work,
	)
	if err != nil {
		t.Fatalf("escaped hash: %v", err)
	}
	if !bytes.Equal(plain, escaped) {
		t.Fatalf("canonical-equivalent hashes differ: %x != %x", plain, escaped)
	}
	if got := work.calls.Load(); got != 1 {
		t.Fatalf("canonical-equivalent hash debits = %d, want 1", got)
	}

	variants := []aggressiveNSEC3Parameters{
		{
			hash:       2,
			iterations: base.iterations,
			salt:       append([]byte(nil), base.salt...),
		},
		{
			hash:       base.hash,
			iterations: base.iterations + 1,
			salt:       append([]byte(nil), base.salt...),
		},
		{
			hash:       base.hash,
			iterations: base.iterations,
			salt:       []byte{0x01, 0x24},
		},
	}
	for i, parameters := range variants {
		if _, err := hashNSEC3MemoTestName("www.example.", parameters, work); err != nil {
			t.Fatalf("tuple variant %d: %v", i, err)
		}
	}
	if got, want := work.calls.Load(), uint32(4); got != want {
		t.Fatalf("partitioned tuple hash debits = %d, want %d", got, want)
	}

	for _, ring := range []struct {
		zone   string
		qclass uint16
	}{
		{zone: "example.", qclass: dns.ClassINET},
		{zone: ".", qclass: dns.ClassINET},
		{zone: "example.", qclass: dns.ClassCHAOS},
	} {
		if _, err := hashNSEC3MemoTestNameForRing(
			"www.example.",
			ring.zone,
			ring.qclass,
			base,
			work,
		); err != nil {
			t.Fatalf("ring variant zone=%q class=%d: %v", ring.zone, ring.qclass, err)
		}
	}
	if got, want := work.calls.Load(), uint32(7); got != want {
		t.Fatalf("partitioned ring hash debits = %d, want %d", got, want)
	}
}

// TestEnsureNSEC3HashMemoPinsOnDeadlineCarrier pins the anchoring contract:
// on a deadline-carried request the memo state lives in the request-lifetime
// pin, so ensuring it derives no context and repeated ensures are free.
func TestEnsureNSEC3HashMemoPinsOnDeadlineCarrier(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()

	ctx := EnsureNSEC3HashMemo(lazy)
	if ctx != context.Context(lazy) {
		t.Fatal("ensuring the memo on a deadline-carried request derived a context")
	}
	memo := NSEC3HashMemoFromContext(ctx)
	if memo == nil {
		t.Fatal("memo not readable back through the pin")
	}
	for scope := NSEC3HashMemoScope(0); scope < nsec3HashMemoScopeCount; scope++ {
		if NSEC3HashMemoFromContextScope(ctx, scope) == nil {
			t.Fatalf("scope %d compartment missing", scope)
		}
	}
	if again := EnsureNSEC3HashMemo(ctx); again != ctx {
		t.Fatal("re-ensuring the memo was not the identity")
	}

	allocs := testing.AllocsPerRun(100, func() {
		if EnsureNSEC3HashMemo(ctx) != ctx {
			t.Fatal("re-ensure diverged")
		}
	})
	if allocs != 0 {
		t.Fatalf("re-ensuring the pinned memo allocated %.0f times, want 0", allocs)
	}
}

func TestInheritNSEC3HashMemosReadsThePinnedParent(t *testing.T) {
	lazy := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer lazy.Cancel()
	parent := EnsureNSEC3HashMemo(lazy)
	memo := NSEC3HashMemoFromContext(parent)
	if memo == nil {
		t.Fatal("parent memo missing")
	}

	detached := InheritNSEC3HashMemos(context.Background(), parent)
	if got := NSEC3HashMemoFromContext(detached); got != memo {
		t.Fatal("detached context did not inherit the pinned memo state")
	}

	// A context already carrying state must keep its own.
	own := EnsureNSEC3HashMemo(context.Background())
	if InheritNSEC3HashMemos(own, parent) != own {
		t.Fatal("inherit overwrote a context that already carries memo state")
	}
}
