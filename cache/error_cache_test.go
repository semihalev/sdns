package cache

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

const (
	testDomain = "www.google.com"
)

func Test_ErrorCache(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock

	cache := NewErrorCache(1, 5)

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	key := Hash(m.Question[0])

	err := cache.Set(key)
	assert.NoError(t, err)

	err = cache.Get(key)
	assert.NoError(t, err)

	fakeClock.Advance(4 * time.Second)
	err = cache.Get(key)
	assert.NoError(t, err)

	fakeClock.Advance(1 * time.Second)
	err = cache.Get(key)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache expired")

	err = cache.Get(key)
	assert.Error(t, err)

	cache = NewErrorCache(0, 5)
	err = cache.Set(key)
	assert.NoError(t, err)

	cache.Remove(key)
	assert.Equal(t, cache.Len(), 0)
}

func Test_ErrorCacheEvict(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock
	cache := NewErrorCache(1024, 5)

	for i := uint64(0); i < 1024; i++ {
		cache.Set(i)
	}

	cache.Set(1024)

	assert.Equal(t, 1024, cache.Len())
}
