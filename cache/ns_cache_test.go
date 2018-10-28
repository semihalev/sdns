package cache

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func Test_NSCache(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock

	cache := NewNSCache()

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	key := Hash(m.Question[0])

	a := NewAuthServer("0.0.0.0:53")
	_ = a.String()

	servers := &AuthServers{List: []*AuthServer{a}}

	err := cache.Set(key, nil, 5, servers)
	assert.NoError(t, err)

	_, err = cache.Get(key)
	assert.NoError(t, err)

	ok := cache.Exists(key)
	assert.Equal(t, ok, true)

	fakeClock.Advance(4 * time.Second)
	_, err = cache.Get(key)
	assert.NoError(t, err)

	fakeClock.Advance(1 * time.Second)
	_, err = cache.Get(key)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache expired")

	_, err = cache.Get(key)
	assert.Error(t, err)

	cache = NewNSCache()
	err = cache.Set(key, nil, 5, nil)
	assert.NoError(t, err)

	cache.Remove(key)
	assert.Equal(t, cache.Length(), 0)

	err = cache.Set(key, nil, 5, nil)
	assert.NoError(t, err)

	fakeClock.Advance(10 * time.Second)
	cache.clear()
	assert.Equal(t, cache.Length(), 0)

}
