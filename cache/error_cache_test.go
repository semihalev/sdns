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

	err = cache.Set(Hash(dns.Question{Name: "test2.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}))
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "capacity full")

	err = cache.Get(key)
	assert.NoError(t, err)

	ok := cache.Exists(key)
	assert.Equal(t, ok, true)

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
	assert.Equal(t, cache.Length(), 0)

	err = cache.Set(key)
	assert.NoError(t, err)

	fakeClock.Advance(10 * time.Second)
	cache.clear()
	assert.Equal(t, cache.Length(), 0)

}
