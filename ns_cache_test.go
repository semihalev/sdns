package main

import (
	"reflect"
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

func Test_ameleCompare(t *testing.T) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	ok := ameleCompare(obj1, obj2)

	assert.Equal(t, false, ok, "equal")

}

func Test_hashCompare(t *testing.T) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	ok := hashCompare(obj1, obj2)

	assert.Equal(t, false, ok, "equal")
}

func Test_byteCompare(t *testing.T) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	ok := byteCompare(obj1, obj2)
	assert.Equal(t, false, ok, "equal")

}

func Benchmark_byteCompare(b *testing.B) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	for i := 0; i < b.N; i++ {
		_ = byteCompare(obj1, obj2)
	}
}

func Benchmark_hashCompare(b *testing.B) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	for i := 0; i < b.N; i++ {
		_ = hashCompare(obj1, obj2)
	}
}

func Benchmark_ameleCompare(b *testing.B) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	for i := 0; i < b.N; i++ {
		_ = ameleCompare(obj1, obj2)
	}
}

func Benchmark_Deep(b *testing.B) {

	obj1 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 2},
	}

	obj2 := []*AuthServer{
		{"domain.com", time.Millisecond * 1},
		{"domain.net", time.Millisecond * 2},
		{"domain.org", time.Millisecond * 2},
		{"domain.info", time.Millisecond * 3},
	}

	for i := 0; i < b.N; i++ {
		_ = reflect.DeepEqual(obj1, obj2)
	}
}
