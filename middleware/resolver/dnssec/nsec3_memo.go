package dnssec

import (
	"context"
	"crypto/sha1" //nolint:gosec // RFC 5155 defines SHA-1 as the NSEC3 hash algorithm.
	"encoding/binary"
	"sync"
	"sync/atomic"
)

// A request tree cannot legitimately need an unbounded number of distinct
// NSEC3 hashes. The recursion-work ledger normally stops much earlier, but
// the independent entry ceiling keeps memoization bounded even when work
// accounting is explicitly disabled.
const maxNSEC3HashMemoEntries = 64

type nsec3HashMemoEntry struct {
	ready chan struct{}
	value []byte
	err   error
}

// NSEC3HashMemo deduplicates identical RFC 5155 hashes across all validation
// and aggressive-cache operations in one request tree. Entries include the
// complete (algorithm, iterations, salt, canonical owner) preimage, so salt
// rotation and parallel parameter chains cannot share a digest.
//
// The memo is concurrency-safe because resolver fan-out can validate sibling
// branches in parallel. A caller that loses the first-computation race waits
// for that exact digest instead of consuming another work unit and crypto
// slot.
type NSEC3HashMemo struct {
	mu      sync.Mutex
	entries map[string]*nsec3HashMemoEntry
	work    atomic.Uint32
}

func newNSEC3HashMemo() *NSEC3HashMemo {
	return &NSEC3HashMemo{}
}

// NewNSEC3HashMemo returns an independently bounded memo. Optional work paths
// use private memos so they cannot pre-populate the required-validation memo
// and thereby bypass request-tree work accounting.
func NewNSEC3HashMemo() *NSEC3HashMemo {
	return newNSEC3HashMemo()
}

func (m *NSEC3HashMemo) load(key string) ([]byte, error, bool) {
	if m == nil {
		return nil, nil, false
	}
	m.mu.Lock()
	entry := m.entries[key]
	m.mu.Unlock()
	if entry == nil {
		return nil, nil, false
	}
	<-entry.ready
	return entry.value, entry.err, true
}

func (m *NSEC3HashMemo) loadOrCompute(
	key string,
	compute func() ([]byte, error),
) ([]byte, error) {
	if m == nil {
		return compute()
	}

	m.mu.Lock()
	if entry := m.entries[key]; entry != nil {
		m.mu.Unlock()
		<-entry.ready
		return entry.value, entry.err
	}
	if len(m.entries) >= maxNSEC3HashMemoEntries {
		m.mu.Unlock()
		return compute()
	}
	if m.entries == nil {
		m.entries = make(map[string]*nsec3HashMemoEntry)
	}
	entry := &nsec3HashMemoEntry{ready: make(chan struct{})}
	m.entries[key] = entry
	m.mu.Unlock()

	value, err := compute()

	m.mu.Lock()
	entry.value = value
	entry.err = err
	if err != nil {
		// Work-limit, saturation, and cancellation failures are transient.
		// Never let one optional miss poison a later required validation.
		delete(m.entries, key)
	}
	close(entry.ready)
	m.mu.Unlock()
	return value, err
}

// TryReserveWork atomically consumes one unit from a request-scoped optional
// hash allowance. Required validation continues to use the recursion ledger;
// optional resolver and cache scopes call this on their private memos so
// constructing another work adapter cannot reset the per-tree ceiling.
func (m *NSEC3HashMemo) TryReserveWork(limit uint32) bool {
	if m == nil || limit == 0 {
		return false
	}
	for {
		used := m.work.Load()
		if used >= limit {
			return false
		}
		if m.work.CompareAndSwap(used, used+1) {
			return true
		}
	}
}

// WorkUsed reports optional hash work reserved through TryReserveWork.
func (m *NSEC3HashMemo) WorkUsed() uint32 {
	if m == nil {
		return 0
	}
	return m.work.Load()
}

// NSEC3HashMemoAccess keeps required and optional accounting directional.
// Read may expose hashes already paid for by required validation. Write is the
// memo populated by this work class. Required work uses the same memo for
// both; optional resolver work reads the required memo but writes privately;
// optional cache work reads and writes only its private memo.
type NSEC3HashMemoAccess struct {
	Read  *NSEC3HashMemo
	Write *NSEC3HashMemo
}

// NSEC3HashMemoProvider is an optional extension to NSEC3Work. Production
// work governors implement it; focused callers that provide only accounting
// retain the original behavior.
type NSEC3HashMemoProvider interface {
	NSEC3HashMemos() NSEC3HashMemoAccess
}

func nsec3HashMemosFromWork(work NSEC3Work) NSEC3HashMemoAccess {
	provider, ok := work.(NSEC3HashMemoProvider)
	if !ok || provider == nil {
		return NSEC3HashMemoAccess{}
	}
	return provider.NSEC3HashMemos()
}

func nsec3HashWithMemo(
	work NSEC3Work,
	key string,
	compute func() ([]byte, error),
) ([]byte, error) {
	access := nsec3HashMemosFromWork(work)
	if value, err, ok := access.Read.load(key); ok {
		return value, err
	}
	if access.Write != nil {
		return access.Write.loadOrCompute(key, compute)
	}
	return compute()
}

type nsec3HashMemoContextKeyType struct{}

var nsec3HashMemoContextKey = &nsec3HashMemoContextKeyType{}

// NSEC3HashMemoScope selects one directional request-tree compartment.
// Required validation owns the shared compartment. Resolver-side optional
// classification may read that compartment but writes only ResolverOptional;
// cache-side optional synthesis is isolated entirely in CacheOptional.
type NSEC3HashMemoScope uint8

const (
	NSEC3HashMemoScopeRequired NSEC3HashMemoScope = iota
	NSEC3HashMemoScopeResolverOptional
	NSEC3HashMemoScopeCacheOptional
	nsec3HashMemoScopeCount
)

type nsec3HashMemoContextState struct {
	memos [nsec3HashMemoScopeCount]NSEC3HashMemo
}

// EnsureNSEC3HashMemo attaches one bounded memo to ctx unless the request tree
// already carries one. Cache and resolver entrypoints both call this helper,
// which keeps cache-less pipelines safe and makes nested Queryer pipelines
// inherit the same digest results.
func EnsureNSEC3HashMemo(ctx context.Context) context.Context {
	if ctx == nil || NSEC3HashMemoFromContext(ctx) != nil {
		return ctx
	}
	return context.WithValue(
		ctx,
		nsec3HashMemoContextKey,
		new(nsec3HashMemoContextState),
	)
}

// NSEC3HashMemoFromContext returns the request tree's memo, if installed.
func NSEC3HashMemoFromContext(ctx context.Context) *NSEC3HashMemo {
	return NSEC3HashMemoFromContextScope(ctx, NSEC3HashMemoScopeRequired)
}

// NSEC3HashMemoFromContextScope returns one request-tree memo compartment.
func NSEC3HashMemoFromContextScope(
	ctx context.Context,
	scope NSEC3HashMemoScope,
) *NSEC3HashMemo {
	if ctx == nil {
		return nil
	}
	value := ctx.Value(nsec3HashMemoContextKey)
	if state, ok := value.(*nsec3HashMemoContextState); ok &&
		scope < nsec3HashMemoScopeCount {
		return &state.memos[scope]
	}
	// Preserve compatibility with contexts created by earlier callers that
	// stored the required memo directly.
	if scope == NSEC3HashMemoScopeRequired {
		memo, _ := value.(*NSEC3HashMemo)
		return memo
	}
	return nil
}

// InheritNSEC3HashMemos copies only the opaque request-tree memo state from
// parent into ctx. Detached-but-retained resolver enrichment uses this instead
// of inheriting the full parent context, which would also leak cancellation,
// response metadata, and unrelated request values into background work.
func InheritNSEC3HashMemos(ctx, parent context.Context) context.Context {
	if ctx == nil || parent == nil ||
		ctx.Value(nsec3HashMemoContextKey) != nil {
		return ctx
	}
	state := parent.Value(nsec3HashMemoContextKey)
	if state == nil {
		return ctx
	}
	return context.WithValue(ctx, nsec3HashMemoContextKey, state)
}

func aggressiveNSEC3HashMemoKey(
	name aggressiveCanonicalName,
	zone aggressiveCanonicalName,
	qclass uint16,
	parameters aggressiveNSEC3Parameters,
) string {
	key := make(
		[]byte,
		0,
		1+2+2+2+len(parameters.salt)+len(zone.wire)+len(name.wire),
	)
	key = append(key, parameters.hash)
	var encoded [2]byte
	binary.BigEndian.PutUint16(encoded[:], parameters.iterations)
	key = append(key, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], qclass)
	key = append(key, encoded[:]...)
	binary.BigEndian.PutUint16(encoded[:], uint16(len(parameters.salt))) //nolint:gosec // DNS salt is at most 255 octets.
	key = append(key, encoded[:]...)
	key = append(key, parameters.salt...)
	key = append(key, zone.wire...)
	key = append(key, name.wire...)
	return string(key)
}

func calculateAggressiveNSEC3Hash(
	name aggressiveCanonicalName,
	parameters aggressiveNSEC3Parameters,
) []byte {
	digest := sha1.New() //nolint:gosec // RFC 5155 requires SHA-1 for NSEC3.
	_, _ = digest.Write(name.wire)
	_, _ = digest.Write(parameters.salt)
	value := digest.Sum(nil)
	for range parameters.iterations {
		digest.Reset()
		_, _ = digest.Write(value)
		_, _ = digest.Write(parameters.salt)
		value = digest.Sum(value[:0])
	}
	return value
}
