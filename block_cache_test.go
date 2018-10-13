package main

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBlockCache(t *testing.T) {
	const (
		testDomain = "www.google.com"
	)

	cache := &BlockCache{
		Backend: make(map[string]bool),
	}

	cache.Set(testDomain, true)

	assert.Equal(t, cache.Exists(testDomain), true)
	assert.Equal(t, cache.Exists(strings.ToUpper(testDomain)), true)

	_, err := cache.Get(testDomain)
	assert.Nil(t, err)

	assert.Equal(t, cache.Length(), 1)

	cache.Remove(testDomain)
	assert.Equal(t, cache.Exists(testDomain), false)

	_, err = cache.Get(testDomain)
	assert.Error(t, err)
}
