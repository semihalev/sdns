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
	key := cache.Hash(m.Question[0])

	a := NewAuthServer("0.0.0.0:53")
	_ = a.String()

	servers := &AuthServers{List: []*AuthServer{a}}

	_, err := nscache.Get(key)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache not found")

	nscache.Set(key, nil, servers)

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
}

func BenchmarkNSCache(b *testing.B) {
	b.ReportAllocs()

	nc := NewNSCache()
	for n := 0; n < b.N; n++ {
		nc.Set(uint64(n), nil, nil)
		nc.Get(uint64(n))
	}
}
