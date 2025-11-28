package authcache

import (
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/cache"
	"github.com/stretchr/testify/assert"
)

func Test_NSCache(t *testing.T) {
	nscache := NewNSCache()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn("example.com."), dns.TypeA)
	key := cache.Key(m.Question[0])

	a := NewAuthServer("0.0.0.0:53", IPv4)
	_ = a.String()

	servers := &AuthServers{List: []*AuthServer{a}}

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

func Test_NSCacheSetTTLClamping(t *testing.T) {
	nscache := NewNSCache()

	key1 := uint64(1)
	key2 := uint64(2)
	key3 := uint64(3)

	servers := &AuthServers{List: []*AuthServer{NewAuthServer("1.2.3.4:53", IPv4)}}

	// Test TTL above maximum (should be clamped to 12h)
	nscache.Set(key1, nil, servers, 24*time.Hour)

	// Test TTL below minimum (should be clamped to 1h)
	nscache.Set(key2, nil, servers, 1*time.Minute)

	// Test TTL within range
	nscache.Set(key3, nil, servers, 6*time.Hour)

	// All should be retrievable
	ns1, err := nscache.Get(key1)
	assert.NoError(t, err)
	assert.NotNil(t, ns1)

	ns2, err := nscache.Get(key2)
	assert.NoError(t, err)
	assert.NotNil(t, ns2)

	ns3, err := nscache.Get(key3)
	assert.NoError(t, err)
	assert.NotNil(t, ns3)
}
