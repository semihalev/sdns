package main

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
)

func Test_NameServerCache(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock

	cache := NewNameServerCache(1)

	err := cache.Set(testDomain, nil, 5, nil)
	assert.NoError(t, err)

	err = cache.Set("test2.com", nil, 5, nil)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache full")

	_, err = cache.Get(testDomain)
	assert.NoError(t, err)

	ok := cache.Exists(testDomain)
	assert.Equal(t, ok, true)

	fakeClock.Advance(5 * time.Second)
	_, err = cache.Get(testDomain)
	assert.NoError(t, err)

	fakeClock.Advance(1 * time.Second)
	_, err = cache.Get(testDomain)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache expired")

	_, err = cache.Get(testDomain)
	assert.Error(t, err)

	cache = NewNameServerCache(0)
	err = cache.Set(testDomain, nil, 5, nil)
	assert.NoError(t, err)

	cache.Remove(testDomain)
}
