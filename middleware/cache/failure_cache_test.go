package cache

import (
	"fmt"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type failureFakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFailureFakeClock() *failureFakeClock {
	return &failureFakeClock{now: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)}
}

func (c *failureFakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *failureFakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

func failureQuestion(name string, qtype uint16) FailureQuestionKey {
	return FailureQuestionKey{
		Question: dns.Question{Name: name, Qtype: qtype, Qclass: dns.ClassINET},
	}
}

func newFailureTestCache(t *testing.T, size int, clock *failureFakeClock) *FailureCache {
	t.Helper()
	cache, err := NewFailureCache(FailureCacheConfig{
		Size:       size,
		InitialTTL: 5 * time.Second,
		MaxTTL:     5 * time.Minute,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFailureCache() error = %v", err)
	}
	t.Cleanup(cache.Stop)
	return cache
}

func TestFailureCacheConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  FailureCacheConfig
		err  error
	}{
		{
			name: "size required",
			cfg:  FailureCacheConfig{},
			err:  errFailureCacheSize,
		},
		{
			name: "negative initial",
			cfg:  FailureCacheConfig{Size: 1, InitialTTL: -time.Second},
			err:  errFailureCacheInitialTTL,
		},
		{
			name: "subsecond initial",
			cfg: FailureCacheConfig{
				Size:       1,
				InitialTTL: time.Second - time.Nanosecond,
				MaxTTL:     time.Second,
			},
			err: errFailureCacheInitialTTL,
		},
		{
			name: "max below initial",
			cfg:  FailureCacheConfig{Size: 1, InitialTTL: 2 * time.Second, MaxTTL: time.Second},
			err:  errFailureCacheMaxTTL,
		},
		{
			name: "max above RFC ceiling",
			cfg: FailureCacheConfig{
				Size:       1,
				InitialTTL: time.Second,
				MaxTTL:     DefaultFailureMaxTTL + time.Nanosecond,
			},
			err: errFailureCacheTTLCeiling,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache, err := NewFailureCache(tt.cfg)
			if err != tt.err {
				t.Fatalf("NewFailureCache() error = %v, want %v", err, tt.err)
			}
			if cache != nil {
				cache.Stop()
			}
		})
	}

	cache, err := NewFailureCache(FailureCacheConfig{Size: 1})
	if err != nil {
		t.Fatalf("NewFailureCache(default TTLs) error = %v", err)
	}
	defer cache.Stop()
	if cache.initialTTL != DefaultFailureInitialTTL {
		t.Errorf("initialTTL = %v, want %v", cache.initialTTL, DefaultFailureInitialTTL)
	}
	if cache.maxTTL != DefaultFailureMaxTTL {
		t.Errorf("maxTTL = %v, want %v", cache.maxTTL, DefaultFailureMaxTTL)
	}
	if cache.now == nil {
		t.Fatal("default clock is nil")
	}
}

func TestFailureCacheBackoffExpiryAndCap(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	key := failureQuestion("WWW.Example", dns.TypeA)
	wants := []time.Duration{
		5 * time.Second,
		10 * time.Second,
		20 * time.Second,
		40 * time.Second,
		80 * time.Second,
		160 * time.Second,
		300 * time.Second,
		300 * time.Second,
	}

	for i, want := range wants {
		hit := cache.RecordQuestion(key, FailureProvenance("transport"), nil)
		if hit.Streak != uint32(i+1) {
			t.Fatalf("generation %d streak = %d, want %d", i+1, hit.Streak, i+1)
		}
		if got := hit.RetryAfter.Sub(clock.Now()); got != want {
			t.Fatalf("generation %d backoff = %v, want %v", i+1, got, want)
		}
		if active, ok := cache.Lookup(key); !ok || active.Streak != hit.Streak {
			t.Fatalf("generation %d Lookup() = %#v, %v; want active streak %d", i+1, active, ok, hit.Streak)
		}

		clock.Advance(want)
		if expired, ok := cache.Lookup(key); ok {
			t.Fatalf("generation %d remained a hit at expiry: %#v", i+1, expired)
		}
		retryKey, ok := cache.RetryKey(key)
		if !ok {
			t.Fatalf("generation %d RetryKey() missed retained history", i+1)
		}
		wantKey := failureQuestionHash(normalizeFailureQuestionKey(key))
		if retryKey != wantKey {
			t.Fatalf("generation %d RetryKey() = %x, want %x", i+1, retryKey, wantKey)
		}
	}
}

func TestFailureCacheInjectableBackoffBounds(t *testing.T) {
	clock := newFailureFakeClock()
	cache, err := NewFailureCache(FailureCacheConfig{
		Size:       8,
		InitialTTL: 2 * time.Second,
		MaxTTL:     7 * time.Second,
		Now:        clock.Now,
	})
	if err != nil {
		t.Fatalf("NewFailureCache() error = %v", err)
	}
	defer cache.Stop()

	key := failureQuestion("www.example.", dns.TypeA)
	for generation, want := range []time.Duration{2 * time.Second, 4 * time.Second, 7 * time.Second, 7 * time.Second} {
		hit := cache.RecordQuestion(key, "timeout", nil)
		if got := hit.RetryAfter.Sub(clock.Now()); got != want {
			t.Fatalf("generation %d backoff = %v, want %v", generation+1, got, want)
		}
		clock.Advance(want)
	}
}

func TestFailureCacheActiveDuplicateIsIdempotent(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 8, clock)
	key := failureQuestion("www.example.", dns.TypeA)

	first := cache.RecordQuestion(key, "first", nil)
	clock.Advance(time.Second)
	duplicate := cache.RecordQuestion(key, "duplicate", nil)
	if duplicate.Streak != 1 {
		t.Fatalf("duplicate streak = %d, want 1", duplicate.Streak)
	}
	if !duplicate.RetryAfter.Equal(first.RetryAfter) {
		t.Fatalf("duplicate deadline = %v, want unchanged %v", duplicate.RetryAfter, first.RetryAfter)
	}
	if duplicate.Provenance != "first" {
		t.Fatalf("duplicate provenance = %q, want original generation provenance", duplicate.Provenance)
	}

	zone := FailureZoneKey{Zone: "example.", Qclass: dns.ClassINET}
	zoneFirst := cache.RecordZone(zone, "zone-first", nil)
	zoneDuplicate := cache.RecordZone(zone, "zone-duplicate", nil)
	if zoneDuplicate.Streak != 1 || !zoneDuplicate.RetryAfter.Equal(zoneFirst.RetryAfter) {
		t.Fatalf("zone duplicate = %#v, want unchanged first generation", zoneDuplicate)
	}
}

func TestFailureCacheLongRecoveryResetsStreak(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 8, clock)
	key := failureQuestion("www.example.", dns.TypeA)

	first := cache.RecordQuestion(key, "first", nil)
	clock.Advance(first.RetryAfter.Sub(clock.Now()))
	second := cache.RecordQuestion(key, "second", nil)
	if second.Streak != 2 {
		t.Fatalf("second generation streak = %d, want 2", second.Streak)
	}

	clock.Advance(second.RetryAfter.Sub(clock.Now()) + cache.maxTTL)
	restarted := cache.RecordQuestion(key, "after-recovery", nil)
	if restarted.Streak != 1 {
		t.Fatalf("streak after long recovery = %d, want 1", restarted.Streak)
	}
	if got := restarted.RetryAfter.Sub(clock.Now()); got != cache.initialTTL {
		t.Fatalf("backoff after long recovery = %v, want %v", got, cache.initialTTL)
	}
	if restarted.Provenance != "after-recovery" {
		t.Fatalf("provenance after long recovery = %q", restarted.Provenance)
	}
}

func TestFailureCacheConcurrentRecordAdvancesOnce(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	key := failureQuestion("www.example.", dns.TypeAAAA)

	const goroutines = 64
	runGeneration := func(wantStreak uint32) {
		t.Helper()
		start := make(chan struct{})
		results := make(chan FailureHit, goroutines)
		var wg sync.WaitGroup
		wg.Add(goroutines)
		for range goroutines {
			go func() {
				defer wg.Done()
				<-start
				results <- cache.RecordQuestion(key, "timeout", nil)
			}()
		}
		close(start)
		wg.Wait()
		close(results)

		for hit := range results {
			if hit.Streak != wantStreak {
				t.Errorf("concurrent RecordQuestion() streak = %d, want %d", hit.Streak, wantStreak)
			}
		}
		active, ok := cache.Lookup(key)
		if !ok || active.Streak != wantStreak {
			t.Fatalf("Lookup() after concurrent record = %#v, %v; want streak %d", active, ok, wantStreak)
		}
	}

	runGeneration(1)
	clock.Advance(5 * time.Second)
	runGeneration(2)
}

func TestFailureCacheConcurrentZoneRecordAdvancesOnce(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	key := FailureZoneKey{Zone: "example.", Qclass: dns.ClassINET}
	cache.RecordZone(key, "timeout", nil)
	clock.Advance(5 * time.Second)

	const goroutines = 64
	start := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for range goroutines {
		go func() {
			defer wg.Done()
			<-start
			hit := cache.RecordZone(key, "timeout", nil)
			if hit.Streak != 2 {
				t.Errorf("concurrent RecordZone() streak = %d, want 2", hit.Streak)
			}
		}()
	}
	close(start)
	wg.Wait()

	hit, ok := cache.Lookup(failureQuestion("www.example.", dns.TypeA))
	if !ok || hit.Kind != FailureKindZone || hit.Streak != 2 {
		t.Fatalf("zone Lookup() after concurrent record = %#v, %v; want streak 2", hit, ok)
	}
}

func TestFailureCacheQuestionKeyIsolation(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	global := failureQuestion("WWW.Example", dns.TypeA)
	cache.RecordQuestion(global, "global", nil)

	canonical := failureQuestion("www.example.", dns.TypeA)
	if _, ok := cache.Lookup(canonical); !ok {
		t.Fatal("canonical equivalent question missed")
	}

	variants := []FailureQuestionKey{
		failureQuestion("www.example.", dns.TypeAAAA),
		{Question: dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}},
		{Question: canonical.Question, CD: true},
		{Question: canonical.Question, Scope: netip.MustParsePrefix("192.0.2.0/24")},
	}
	for _, variant := range variants {
		if hit, ok := cache.Lookup(variant); ok {
			t.Errorf("isolated variant %#v hit %#v", variant, hit)
		}
	}

	scoped := canonical
	scoped.Scope = netip.MustParsePrefix("192.0.2.129/24")
	cache.RecordQuestion(scoped, "scoped", nil)
	equivalentScope := canonical
	equivalentScope.Scope = netip.MustParsePrefix("192.0.2.1/24")
	if hit, ok := cache.Lookup(equivalentScope); !ok || hit.Provenance != "scoped" {
		t.Fatalf("masked equivalent scope Lookup() = %#v, %v", hit, ok)
	}
	differentScope := canonical
	differentScope.Scope = netip.MustParsePrefix("192.0.2.128/25")
	if hit, ok := cache.Lookup(differentScope); ok {
		t.Fatalf("different scope hit %#v", hit)
	}

	globalZero := canonical
	globalZero.Scope = netip.MustParsePrefix("0.0.0.0/0")
	if hit, ok := cache.Lookup(globalZero); !ok || hit.Provenance != "global" {
		t.Fatalf("/0 scope Lookup() = %#v, %v; want global hit", hit, ok)
	}
}

func TestFailureCacheZoneClosestAncestorAndSharedReachability(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	cache.RecordZone(FailureZoneKey{Zone: "EXAMPLE", Qclass: dns.ClassINET}, "parent", nil)
	cache.RecordZone(FailureZoneKey{Zone: "Sub.Example.", Qclass: dns.ClassINET}, "child", nil)

	tests := []struct {
		name string
		key  FailureQuestionKey
		want FailureProvenance
	}{
		{
			name: "closest descendant",
			key:  failureQuestion("www.sub.example.", dns.TypeA),
			want: "child",
		},
		{
			name: "zone apex",
			key:  failureQuestion("sub.example.", dns.TypeNS),
			want: "child",
		},
		{
			name: "parent descendant",
			key:  failureQuestion("www.example.", dns.TypeAAAA),
			want: "parent",
		},
		{
			name: "CD independent",
			key: FailureQuestionKey{
				Question: dns.Question{Name: "www.sub.example.", Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
				CD:       true,
			},
			want: "child",
		},
		{
			name: "ECS independent",
			key: FailureQuestionKey{
				Question: dns.Question{Name: "www.sub.example.", Qtype: dns.TypeMX, Qclass: dns.ClassINET},
				Scope:    netip.MustParsePrefix("2001:db8::/56"),
			},
			want: "child",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hit, ok := cache.Lookup(tt.key)
			if !ok || hit.Kind != FailureKindZone || hit.Provenance != tt.want {
				t.Fatalf("Lookup() = %#v, %v; want zone provenance %q", hit, ok, tt.want)
			}
		})
	}

	misses := []FailureQuestionKey{
		failureQuestion("badexample.", dns.TypeA),
		failureQuestion("example.net.", dns.TypeA),
		{Question: dns.Question{Name: "www.example.", Qtype: dns.TypeA, Qclass: dns.ClassCHAOS}},
	}
	for _, miss := range misses {
		if hit, ok := cache.Lookup(miss); ok {
			t.Errorf("uncovered question %#v hit %#v", miss, hit)
		}
	}
}

func TestFailureCacheRetryKeyGroupsExpiredZoneDescendants(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	child := FailureZoneKey{Zone: "sub.example.", Qclass: dns.ClassINET}
	parent := FailureZoneKey{Zone: "example.", Qclass: dns.ClassINET}

	cache.RecordZone(child, "child", nil)
	clock.Advance(4 * time.Second)
	cache.RecordZone(parent, "parent", nil)
	clock.Advance(time.Second)

	queryOne := failureQuestion("r1.sub.example.", dns.TypeA)
	queryTwo := failureQuestion("r2.sub.example.", dns.TypeAAAA)
	if hit, ok := cache.Lookup(queryOne); !ok || hit.Provenance != "parent" {
		t.Fatalf("expired child did not fall back to active parent: %#v, %v", hit, ok)
	}
	if key, ok := cache.RetryKey(queryOne); ok {
		t.Fatalf("RetryKey() = %x while an ancestor zone is active", key)
	}

	clock.Advance(4 * time.Second)
	keyOne, ok := cache.RetryKey(queryOne)
	if !ok {
		t.Fatal("RetryKey(queryOne) missed expired zone state")
	}
	keyTwo, ok := cache.RetryKey(queryTwo)
	if !ok {
		t.Fatal("RetryKey(queryTwo) missed expired zone state")
	}
	if keyOne != keyTwo {
		t.Fatalf("random-QNAME retry keys differ: %x != %x", keyOne, keyTwo)
	}
	want := failureZoneHash(normalizeFailureZoneKey(child))
	if keyOne != want {
		t.Fatalf("zone retry key = %x, want closest ancestor key %x", keyOne, want)
	}

	cache.RecordQuestion(queryOne, "exact-one", nil)
	cache.RecordQuestion(queryTwo, "exact-two", nil)
	clock.Advance(5 * time.Second)
	groupedOne, ok := cache.RetryKey(queryOne)
	if !ok {
		t.Fatal("RetryKey(queryOne) missed expired exact+zone history")
	}
	groupedTwo, ok := cache.RetryKey(queryTwo)
	if !ok {
		t.Fatal("RetryKey(queryTwo) missed expired exact+zone history")
	}
	if groupedOne != want || groupedTwo != want {
		t.Fatalf("exact histories defeated zone grouping: keys %x/%x, want zone %x", groupedOne, groupedTwo, want)
	}

	if !cache.ResetZone(child) || !cache.ResetZone(parent) {
		t.Fatal("failed to remove zone histories for exact fallback check")
	}
	exactKey, ok := cache.RetryKey(queryOne)
	if !ok {
		t.Fatal("RetryKey(queryOne) missed expired exact history without a zone state")
	}
	wantExact := failureQuestionHash(normalizeFailureQuestionKey(queryOne))
	if exactKey != wantExact {
		t.Fatalf("exact-only retry key = %x, want %x", exactKey, wantExact)
	}
}

func TestFailureCacheResetAndResetMatching(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 32, clock)
	key := failureQuestion("www.sub.example.", dns.TypeA)
	cache.RecordQuestion(key, "exact", nil)
	cache.RecordZone(FailureZoneKey{Zone: "sub.example.", Qclass: dns.ClassINET}, "child", nil)
	cache.RecordZone(FailureZoneKey{Zone: "example.", Qclass: dns.ClassINET}, "parent", nil)
	cache.RecordZone(FailureZoneKey{Zone: ".", Qclass: dns.ClassINET}, "root", nil)
	unrelated := failureQuestion("www.other.", dns.TypeA)
	cache.RecordQuestion(unrelated, "unrelated", nil)

	if removed := cache.ResetMatching(key); removed != 4 {
		t.Fatalf("ResetMatching() removed %d states, want 4", removed)
	}
	if hit, ok := cache.Lookup(key); ok {
		t.Fatalf("reset question still hit %#v", hit)
	}
	if hit, ok := cache.Lookup(unrelated); !ok || hit.Provenance != "unrelated" {
		t.Fatalf("ResetMatching removed unrelated exact state: %#v, %v", hit, ok)
	}
	restarted := cache.RecordQuestion(key, "recovered-then-failed", nil)
	if restarted.Streak != 1 {
		t.Fatalf("record after reset streak = %d, want 1", restarted.Streak)
	}

	if !cache.ResetQuestion(key) {
		t.Fatal("ResetQuestion() did not delete matching state")
	}
	if cache.ResetQuestion(key) {
		t.Fatal("ResetQuestion() deleted an absent state")
	}
}

func TestFailureCacheFullPreimageVerification(t *testing.T) {
	clock := newFailureFakeClock()
	cache := newFailureTestCache(t, 16, clock)
	target := normalizeFailureQuestionKey(failureQuestion("target.example.", dns.TypeA))
	collision := normalizeFailureQuestionKey(failureQuestion("collision.example.", dns.TypeAAAA))
	targetHash := failureQuestionHash(target)
	injected := &failureEntry{
		kind:       FailureKindQuestion,
		provenance: "collision",
		streak:     7,
		retryAfter: clock.Now().Add(time.Hour),
		question:   collision,
	}
	cache.entries.Add(targetHash, injected)

	if hit, ok := cache.Lookup(target); ok {
		t.Fatalf("question hash collision produced hit %#v", hit)
	}
	if key, ok := cache.RetryKey(target); ok {
		t.Fatalf("question hash collision produced retry key %x", key)
	}
	if cache.ResetQuestion(target) {
		t.Fatal("ResetQuestion removed a colliding preimage")
	}
	if got, ok := cache.entries.Get(targetHash); !ok || got != injected {
		t.Fatal("colliding entry changed after verified miss/reset")
	}

	zoneTarget := normalizeFailureZoneKey(FailureZoneKey{Zone: "zone.example.", Qclass: dns.ClassINET})
	zoneCollision := normalizeFailureZoneKey(FailureZoneKey{Zone: "other.example.", Qclass: dns.ClassINET})
	zoneHash := failureZoneHash(zoneTarget)
	injectedZone := &failureEntry{
		kind:       FailureKindZone,
		provenance: "zone-collision",
		streak:     3,
		retryAfter: clock.Now().Add(time.Hour),
		zone:       zoneCollision,
	}
	cache.entries.Add(zoneHash, injectedZone)

	if hit, ok := cache.Lookup(failureQuestion("www.zone.example.", dns.TypeA)); ok {
		t.Fatalf("zone hash collision produced hit %#v", hit)
	}
	if cache.ResetZone(zoneTarget) {
		t.Fatal("ResetZone removed a colliding preimage")
	}
	if got, ok := cache.entries.Get(zoneHash); !ok || got != injectedZone {
		t.Fatal("zone collision entry changed after verified miss/reset")
	}
}

func TestFailureCacheBounded(t *testing.T) {
	clock := newFailureFakeClock()
	const size = 8
	cache := newFailureTestCache(t, size, clock)

	for i := range 500 {
		cache.RecordQuestion(failureQuestion(fmt.Sprintf("q-%d.example.", i), dns.TypeA), "exact", nil)
		cache.RecordZone(FailureZoneKey{
			Zone:   fmt.Sprintf("z-%d.example.", i),
			Qclass: dns.ClassINET,
		}, "zone", nil)
		if got := cache.Len(); got > size {
			t.Fatalf("failure cache grew to %d entries, limit %d", got, size)
		}
	}
}

func TestFailureHitResponseIsCleanSERVFAILWithOnlyEDE13(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.example.", dns.TypeA)
	req.Id = 4242
	req.CheckingDisabled = true
	req.AuthenticatedData = true
	req.SetEdns0(1232, true)
	reqOPT := req.IsEdns0()
	reqOPT.Option = append(reqOPT.Option,
		&dns.EDNS0_COOKIE{Cookie: "0123456789abcdef"},
		&dns.EDNS0_SUBNET{
			Code:          dns.EDNS0SUBNET,
			Family:        1,
			SourceNetmask: 24,
			Address:       net.ParseIP("192.0.2.1"),
		},
		&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeDNSBogus, ExtraText: "do not copy"},
	)
	req.Extra = append(req.Extra, &dns.TXT{
		Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeTXT, Class: dns.ClassINET},
		Txt: []string{"do not copy"},
	})

	resp := (FailureHit{}).Response(req)
	if resp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("Rcode = %s, want SERVFAIL", dns.RcodeToString[resp.Rcode])
	}
	if resp.Id != req.Id || !resp.Response {
		t.Fatalf("response header = %#v, want reply ID %d", resp.MsgHdr, req.Id)
	}
	if !resp.RecursionAvailable || !resp.RecursionDesired || !resp.CheckingDisabled {
		t.Fatalf("reply request bits/RA not preserved or set: %#v", resp.MsgHdr)
	}
	if resp.AuthenticatedData {
		t.Fatal("AD is set on cached failure")
	}
	if len(resp.Answer) != 0 || len(resp.Ns) != 0 {
		t.Fatalf("cached failure carried records: answer=%d authority=%d", len(resp.Answer), len(resp.Ns))
	}
	if len(resp.Extra) != 1 {
		t.Fatalf("additional count = %d, want one clean OPT", len(resp.Extra))
	}
	opt, ok := resp.Extra[0].(*dns.OPT)
	if !ok {
		t.Fatalf("additional RR = %T, want OPT", resp.Extra[0])
	}
	if opt.UDPSize() != 1232 || !opt.Do() {
		t.Fatalf("response OPT size/DO = %d/%v, want 1232/true", opt.UDPSize(), opt.Do())
	}
	if len(opt.Option) != 1 {
		t.Fatalf("response options = %#v, want only EDE", opt.Option)
	}
	ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
	if !ok {
		t.Fatalf("response option = %T, want EDE", opt.Option[0])
	}
	if ede.InfoCode != dns.ExtendedErrorCodeCachedError || ede.ExtraText != failureCacheEDEText {
		t.Fatalf("EDE = %#v, want code 13 and stable text %q", ede, failureCacheEDEText)
	}
}

func TestFailureHitResponseWithoutEDNSHasNoEDE(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("www.example.", dns.TypeA)
	resp := (FailureHit{}).Response(req)

	if resp.Rcode != dns.RcodeServerFailure || !resp.RecursionAvailable || resp.AuthenticatedData {
		t.Fatalf("response header = %#v", resp.MsgHdr)
	}
	if len(resp.Extra) != 0 || resp.IsEdns0() != nil {
		t.Fatalf("non-EDNS request got additional data: %#v", resp.Extra)
	}
}
