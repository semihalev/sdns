package main

import (
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/assert"
)

func Test_ErrorCache(t *testing.T) {
	fakeClock := clockwork.NewFakeClock()
	WallClock = fakeClock

	cache := NewErrorCache(1, 5)

	err := cache.Set(testDomain)
	assert.NoError(t, err)

	err = cache.Set("test2.com")
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache full")

	err = cache.Get(testDomain)
	assert.NoError(t, err)

	ok := cache.Exists(testDomain)
	assert.Equal(t, ok, true)

	fakeClock.Advance(5 * time.Second)
	err = cache.Get(testDomain)
	assert.NoError(t, err)

	fakeClock.Advance(1 * time.Second)
	err = cache.Get(testDomain)
	assert.Error(t, err)
	assert.Equal(t, err.Error(), "cache expired")

	err = cache.Get(testDomain)
	assert.Error(t, err)

	cache = NewErrorCache(0, 5)
	err = cache.Set(testDomain)
	assert.NoError(t, err)

	cache.Remove(testDomain)
}
