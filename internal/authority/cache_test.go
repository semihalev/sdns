package authority

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/stretchr/testify/assert"
)

func Test_Cache(t *testing.T) {
	nscache := NewCache()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	key := cache.Key(m.Question[0])

	a := NewServer("0.0.0.0:53", IPv4)
	_ = a.String()

	servers := &Servers{List: []*Server{a}}

	_, err := nscache.Get(key)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache not found")

	nscache.Set(key, nil, servers, time.Hour)

	_, err = nscache.Get(key)
	assert.NoError(t, err)

	nscache.now = func() time.Time {
		return time.Now().Add(30 * time.Minute)
	}
	_, err = nscache.Get(key)
	assert.NoError(t, err)

	nscache.now = func() time.Time {
		return time.Now().Add(2 * time.Hour)
	}
	_, err = nscache.Get(key)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache expired")

	_, err = nscache.Get(key)
	assert.Error(t, err)

	nscache.Remove(key)
}

// Test_CacheSetTTL locks in the ghost-domain (GHSA-mqfw-f48p-2vc8) lease
// semantics: the parent-granted TTL is honoured exactly (no lower floor),
// only the 12h ceiling is applied, and non-positive TTLs are not cached. The
// old code floored any sub-1h TTL to one hour, which is what let a withdrawn
// child survive.
func Test_CacheSetTTL(t *testing.T) {
	nscache := NewCache()
	base := time.Now()
	nscache.now = func() time.Time { return base }

	servers := &Servers{List: []*Server{NewServer("1.2.3.4:53", IPv4)}}

	const (
		capped = uint64(1) // 24h -> clamped to 12h
		short  = uint64(2) // 4s  -> honoured exactly (used to be floored to 1h)
		zero   = uint64(3) // 0   -> not cached
		neg    = uint64(4) // <0  -> not cached
	)

	nscache.Set(capped, nil, servers, 24*time.Hour)
	nscache.Set(short, nil, servers, 4*time.Second)
	nscache.Set(zero, nil, servers, 0)
	nscache.Set(neg, nil, servers, -time.Second)

	// A 4s delegation is valid at 3s and expired by 5s — proving it was NOT
	// inflated to the old one-hour floor.
	nscache.now = func() time.Time { return base.Add(3 * time.Second) }
	if _, err := nscache.Get(short); err != nil {
		t.Fatalf("4s delegation should be valid at 3s: %v", err)
	}
	nscache.now = func() time.Time { return base.Add(5 * time.Second) }
	if _, err := nscache.Get(short); err == nil {
		t.Fatal("4s delegation must be expired by 5s (old code floored it to 1h)")
	}

	// 24h TTL is capped to 12h: valid at 11h, expired by 13h.
	nscache.now = func() time.Time { return base.Add(11 * time.Hour) }
	if _, err := nscache.Get(capped); err != nil {
		t.Fatalf("24h TTL should be capped to 12h and valid at 11h: %v", err)
	}
	nscache.now = func() time.Time { return base.Add(13 * time.Hour) }
	if _, err := nscache.Get(capped); err == nil {
		t.Fatal("24h TTL capped to 12h must be expired by 13h")
	}

	// Non-positive TTLs are never cached.
	nscache.now = func() time.Time { return base }
	if _, err := nscache.Get(zero); err == nil {
		t.Fatal("zero-TTL delegation must not be cached")
	}
	if _, err := nscache.Get(neg); err == nil {
		t.Fatal("negative-TTL delegation must not be cached")
	}
}

// Test_CacheSetUntil locks in the absolute-deadline semantics that the
// Phoenix T2 inheritance fix depends on: the supplied deadline is stored
// verbatim (never re-anchored), past/equal deadlines are not cached, and the
// 12h ceiling still applies.
func Test_CacheSetUntil(t *testing.T) {
	nscache := NewCache()
	base := time.Now()
	nscache.now = func() time.Time { return base }

	servers := &Servers{List: []*Server{NewServer("1.2.3.4:53", IPv4)}}

	const (
		exact  = uint64(1) // stored verbatim
		past   = uint64(2) // before now -> not cached
		atNow  = uint64(3) // equal to now -> not cached
		capped = uint64(4) // beyond 12h -> capped
	)

	deadline := base.Add(10 * time.Second)
	nscache.SetUntil(exact, nil, servers, deadline)
	nscache.SetUntil(past, nil, servers, base.Add(-time.Second))
	nscache.SetUntil(atNow, nil, servers, base)
	nscache.SetUntil(capped, nil, servers, base.Add(24*time.Hour))

	// The absolute deadline is stored exactly as supplied.
	d, err := nscache.Get(exact)
	if err != nil {
		t.Fatalf("SetUntil entry should be cached: %v", err)
	}
	if !d.ExpiresAt.Equal(deadline) {
		t.Fatalf("ExpiresAt = %v, want the supplied deadline %v (re-anchored?)", d.ExpiresAt, deadline)
	}

	// Valid strictly before the deadline, expired exactly at it.
	nscache.now = func() time.Time { return deadline.Add(-time.Nanosecond) }
	if _, err := nscache.Get(exact); err != nil {
		t.Fatalf("entry should be valid just before its deadline: %v", err)
	}
	nscache.now = func() time.Time { return deadline }
	if _, err := nscache.Get(exact); err == nil {
		t.Fatal("entry must be expired exactly at its deadline")
	}

	// Past and now-equal deadlines are never cached.
	nscache.now = func() time.Time { return base }
	if _, err := nscache.Get(past); err == nil {
		t.Fatal("past deadline must not be cached")
	}
	if _, err := nscache.Get(atNow); err == nil {
		t.Fatal("deadline equal to now must not be cached")
	}

	// A deadline beyond the ceiling is capped to now+12h.
	d, err = nscache.Get(capped)
	if err != nil {
		t.Fatalf("capped entry should be cached: %v", err)
	}
	if want := base.Add(12 * time.Hour); !d.ExpiresAt.Equal(want) {
		t.Fatalf("ExpiresAt = %v, want ceiling %v", d.ExpiresAt, want)
	}
}
