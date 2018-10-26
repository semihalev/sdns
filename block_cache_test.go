package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_BlockCache(t *testing.T) {
	const (
		testDomain = "www.google.com."
	)

	cache := NewBlockCache()

	cache.Set(testDomain, true)

	assert.Equal(t, cache.Exists(testDomain), true)
	assert.Equal(t, cache.Exists(strings.ToUpper(testDomain)), true)

	_, err := cache.Get(testDomain)
	assert.NoError(t, err)

	assert.Equal(t, cache.Length(), 1)

	if exists := cache.Exists(fmt.Sprintf("%sfuzz", testDomain)); exists {
		t.Error("fuzz existed in block cache")
	}

	if cacheLen := cache.Length(); cacheLen != 1 {
		t.Error("invalid length: ", cacheLen)
	}

	cache.Remove(testDomain)
	assert.Equal(t, cache.Exists(testDomain), false)

	_, err = cache.Get(testDomain)
	assert.Error(t, err)
}
