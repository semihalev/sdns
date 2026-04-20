package middleware

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/mock"
)

// noopHandler is a handler that just forwards. This isolates the
// benchmark to Chain.Next + interface dispatch; no allocation or DNS
// logic inside.
type noopHandler struct{ n string }

func (h *noopHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *noopHandler) Name() string                            { return h.n }

func buildChain(n int) *Chain {
	handlers := make([]Handler, n)
	for i := range handlers {
		handlers[i] = &noopHandler{n: "h" + strconv.Itoa(i)}
	}
	return NewChain(handlers)
}

// BenchmarkChainNext walks a full middleware chain. The realistic
// production chain is ~15 handlers (see registry.go), so we also
// include that size explicitly.
func BenchmarkChainNext(b *testing.B) {
	for _, n := range []int{1, 5, 15, 32} {
		b.Run(strconv.Itoa(n), func(b *testing.B) {
			ch := buildChain(n)
			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)
			w := mock.NewWriter("udp", "127.0.0.1:0")

			ctx := context.Background()
			b.ReportAllocs()
			for b.Loop() {
				ch.Reset(w, req)
				ch.Next(ctx)
			}
		})
	}
}

// BenchmarkGet measures lookup of a handler by name, post-Setup.
// The new Pipeline.Get is an O(1) map lookup on an atomic-loaded pointer.
func BenchmarkGet(b *testing.B) {
	Reset()
	b.Cleanup(Reset)

	for i := range 15 {
		name := "h" + strconv.Itoa(i)
		Register(name, func(n string) Constructor {
			return func(*config.Config) Handler { return &noopHandler{n: n} }
		}(name))
	}
	Setup(&config.Config{})

	b.ReportAllocs()
	for b.Loop() {
		_ = Get("h7")
	}
}

// BenchmarkGet_Legacy reproduces the 1.6.2 Get() behaviour — linear scan
// over the registered handlers under an RWMutex — to quantify the delta
// versus the new atomic-pointer + map lookup. The reproduction walks the
// same Pipeline.handlers that Get uses, but through a locked index search
// instead of the byName map.
func BenchmarkGet_Legacy(b *testing.B) {
	Reset()
	b.Cleanup(Reset)

	for i := range 15 {
		name := "h" + strconv.Itoa(i)
		Register(name, func(n string) Constructor {
			return func(*config.Config) Handler { return &noopHandler{n: n} }
		}(name))
	}
	Setup(&config.Config{})

	var mu sync.RWMutex // simulate the old package-level RWMutex
	handlers := Handlers()

	legacyGet := func(name string) Handler {
		mu.RLock()
		defer mu.RUnlock()
		for _, h := range handlers {
			if h.Name() == name {
				return h
			}
		}
		return nil
	}

	b.ReportAllocs()
	for b.Loop() {
		_ = legacyGet("h7")
	}
}
