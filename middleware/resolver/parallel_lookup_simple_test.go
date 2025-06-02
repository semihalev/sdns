package resolver

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/semihalev/sdns/authcache"
	"github.com/stretchr/testify/assert"
)

func TestCalculateDelay(t *testing.T) {
	r := &Resolver{}

	tests := []struct {
		name     string
		server   *authcache.AuthServer
		position int
		maxDelay time.Duration
	}{
		{
			name:     "First server with no RTT",
			server:   &authcache.AuthServer{},
			position: 0,
			maxDelay: 50 * time.Millisecond,
		},
		{
			name: "Server with known RTT",
			server: func() *authcache.AuthServer {
				s := &authcache.AuthServer{}
				atomic.StoreInt64(&s.Rtt, int64(100*time.Millisecond))
				return s
			}(),
			position: 1,
			maxDelay: 100 * time.Millisecond,
		},
		{
			name:     "High position server",
			server:   &authcache.AuthServer{},
			position: 10,
			maxDelay: 300 * time.Millisecond, // Should be capped
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			delay := r.calculateDelay(tt.server, tt.position)
			assert.True(t, delay <= tt.maxDelay, "Delay should not exceed max")
			assert.True(t, delay >= 0, "Delay should be positive")
		})
	}
}

func TestCalculateTimeout(t *testing.T) {
	r := &Resolver{netTimeout: 2 * time.Second}

	tests := []struct {
		name       string
		server     *authcache.AuthServer
		minTimeout time.Duration
		maxTimeout time.Duration
	}{
		{
			name:       "Server with no RTT data",
			server:     &authcache.AuthServer{},
			minTimeout: 100 * time.Millisecond,
			maxTimeout: 5 * time.Second,
		},
		{
			name: "Fast server",
			server: func() *authcache.AuthServer {
				s := &authcache.AuthServer{}
				atomic.StoreInt64(&s.Rtt, int64(10*time.Millisecond))
				return s
			}(),
			minTimeout: 100 * time.Millisecond,
			maxTimeout: 200 * time.Millisecond,
		},
		{
			name: "Slow server",
			server: func() *authcache.AuthServer {
				s := &authcache.AuthServer{}
				atomic.StoreInt64(&s.Rtt, int64(2*time.Second))
				return s
			}(),
			minTimeout: 1 * time.Second,
			maxTimeout: 5 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			timeout := r.calculateTimeout(tt.server)
			assert.True(t, timeout >= tt.minTimeout, "Timeout should be at least min")
			assert.True(t, timeout <= tt.maxTimeout, "Timeout should not exceed max")
		})
	}
}

func BenchmarkCalculateDelay(b *testing.B) {
	r := &Resolver{}
	server := &authcache.AuthServer{}
	atomic.StoreInt64(&server.Rtt, int64(50*time.Millisecond))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.calculateDelay(server, i%10)
	}
}

func BenchmarkCalculateTimeout(b *testing.B) {
	r := &Resolver{netTimeout: 2 * time.Second}
	server := &authcache.AuthServer{}
	atomic.StoreInt64(&server.Rtt, int64(50*time.Millisecond))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.calculateTimeout(server)
	}
}
