package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestBlockCache(t *testing.T) {
	const (
		testDomain = "www.google.com"
	)

	cache := &BlockCache{
		Backend: make(map[string]bool),
	}

	cache.Set(testDomain, true)

	if exists := cache.Exists(testDomain); !exists {
		t.Error(testDomain, "didnt exist in block cache")
	}

	if exists := cache.Exists(strings.ToUpper(testDomain)); !exists {
		t.Error(strings.ToUpper(testDomain), "didnt exist in block cache")
	}

	if _, err := cache.Get(testDomain); err != nil {
		t.Error(err)
	}

	if exists := cache.Exists(fmt.Sprintf("%sfuzz", testDomain)); exists {
		t.Error("fuzz existed in block cache")
	}
}
