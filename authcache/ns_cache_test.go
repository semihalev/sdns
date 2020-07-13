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
