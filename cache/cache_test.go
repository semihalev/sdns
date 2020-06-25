// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package cache

import (
	"fmt"
	"testing"
)

func TestCacheAddAndGet(t *testing.T) {
	c := New(4)
	c.Add(1, 1)

	if _, found := c.Get(1); !found {
		t.Fatal("Failed to find inserted record")
	}
}

func TestCacheLen(t *testing.T) {
	c := New(4)

	c.Add(1, 1)
	if l := c.Len(); l != 1 {
		t.Fatalf("Cache size should %d, got %d", 1, l)
	}

	c.Add(1, 1)
	if l := c.Len(); l != 1 {
		t.Fatalf("Cache size should %d, got %d", 1, l)
	}

	c.Add(2, 2)
	if l := c.Len(); l != 2 {
		t.Fatalf("Cache size should %d, got %d", 2, l)
	}
}

func TestCacheRemove(t *testing.T) {
	c := New(4)

	c.Add(1, 1)
	if l := c.Len(); l != 1 {
		t.Fatalf("Cache size should %d, got %d", 1, l)
	}

	c.Remove(1)
	if l := c.Len(); l != 0 {
		t.Fatalf("Cache size should %d, got %d", 1, l)
	}
}

func BenchmarkCacheGet(b *testing.B) {
	const items = 1 << 16
	c := New(12 * items)
	v := []byte("xyza")
	for i := 0; i < items; i++ {
		c.Add(uint64(i), v)
	}

	b.ReportAllocs()
	b.SetBytes(items)
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			for i := 0; i < items; i++ {
				b, _ := c.Get(uint64(i))
				if string(b.([]byte)) != string(v) {
					panic(fmt.Errorf("BUG: invalid value obtained; got %q; want %q", b, v))
				}
			}
		}
	})
}

func BenchmarkCacheSet(b *testing.B) {
	const items = 1 << 16
	c := New(12 * items)
	b.ReportAllocs()
	b.SetBytes(items)
	b.RunParallel(func(pb *testing.PB) {
		v := []byte("xyza")
		for pb.Next() {
			for i := 0; i < items; i++ {
				c.Add(uint64(i), v)
			}
		}
	})
}

func BenchmarkCacheSetGet(b *testing.B) {
	const items = 1 << 16
	c := New(12 * items)
	b.ReportAllocs()
	b.SetBytes(2 * items)
	b.RunParallel(func(pb *testing.PB) {
		v := []byte("xyza")
		for pb.Next() {
			for i := 0; i < items; i++ {
				c.Add(uint64(i), v)
			}
			for i := 0; i < items; i++ {
				b, _ := c.Get(uint64(i))
				if string(b.([]byte)) != string(v) {
					panic(fmt.Errorf("BUG: invalid value obtained; got %q; want %q", b, v))
				}
			}
		}
	})
}
