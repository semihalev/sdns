package cache

import (
	"errors"

	"github.com/jonboulle/clockwork"
)

var (
	// WallClock is the wall clock
	WallClock = clockwork.NewRealClock()

	// ErrCacheNotFound error
	ErrCacheNotFound = errors.New("cache not found")
	// ErrCacheExpired error
	ErrCacheExpired = errors.New("cache expired")
)
