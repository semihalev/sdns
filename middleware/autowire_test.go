package middleware

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

// providerHandler implements Handler + StoreProvider (+ optional
// extra roles via embedded bool flags).
type providerHandler struct {
	n       string
	store   Store
	limiter DNSSECCryptoLimiter
}

func (h *providerHandler) Name() string                            { return h.n }
func (h *providerHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *providerHandler) Store() Store                            { return h.store }
func (h *providerHandler) DNSSECCryptoLimiter() DNSSECCryptoLimiter {
	return h.limiter
}

// setterHandler implements QueryerSetter, PrefetchQueryerSetter,
// and StoreSetter — used to pin that autoWire invokes all three.
type setterHandler struct {
	n      string
	gotQ   Queryer
	gotPQ  Queryer
	gotStr Store
	gotLim DNSSECCryptoLimiter
}

func (h *setterHandler) Name() string                            { return h.n }
func (h *setterHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *setterHandler) SetQueryer(q Queryer)                    { h.gotQ = q }
func (h *setterHandler) SetPrefetchQueryer(q Queryer)            { h.gotPQ = q }
func (h *setterHandler) SetStore(s Store)                        { h.gotStr = s }
func (h *setterHandler) SetDNSSECCryptoLimiter(l DNSSECCryptoLimiter) {
	h.gotLim = l
}

// clientOnlyHandler reports ClientOnly()==true; autoWire must
// exclude it from both queryerSub and prefetchSub.
type clientOnlyHandler struct{ n string }

func (h *clientOnlyHandler) Name() string                            { return h.n }
func (h *clientOnlyHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *clientOnlyHandler) ClientOnly() bool                        { return true }

// nopStore implements Store.
type nopStore struct{}

func (nopStore) Get(*dns.Msg) (*dns.Msg, bool)             { return nil, false }
func (nopStore) SetFromResponse(*dns.Msg, bool, time.Time) {}

type nopCryptoLimiter struct{}

func (nopCryptoLimiter) TryAcquire() (func(), bool) { return func() {}, true }

type typedNilCryptoLimiter struct{}

func (*typedNilCryptoLimiter) TryAcquire() (func(), bool) { return nil, false }

func TestAutoWire_NilSafe(t *testing.T) {
	var p *Pipeline
	// Must not panic.
	p.autoWire()
}

// TestAutoWire_FullWiring covers: ClientOnly filter, StoreProvider
// discovery, and all three *Setter paths (QueryerSetter,
// PrefetchQueryerSetter, StoreSetter) firing against the same
// handler.
func TestAutoWire_FullWiring(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	st := nopStore{}
	limiter := nopCryptoLimiter{}
	prov := &providerHandler{n: "cache", store: st, limiter: limiter}
	setter := &setterHandler{n: "resolver"}
	co := &clientOnlyHandler{n: "metrics"}

	Register("metrics", func(*config.Config) Handler { return co })
	Register("cache", func(*config.Config) Handler { return prov })
	Register("resolver", func(*config.Config) Handler { return setter })

	Setup(&config.Config{})

	// metrics is ClientOnly → must be missing from both sub-pipelines.
	pipe := GlobalPipeline()
	sub := pipe.SubPipeline("metrics")
	if sub.Get("metrics") != nil {
		t.Errorf("sub.Get('metrics') = %v, want nil", sub.Get("metrics"))
	}

	// Setter got all three wiring calls.
	if setter.gotQ == nil {
		t.Errorf("%s: setter.gotQ is nil", "SetQueryer not called")
	}
	if setter.gotPQ == nil {
		t.Errorf("%s: setter.gotPQ is nil", "SetPrefetchQueryer not called")
	}
	if !reflect.DeepEqual(Store(st), setter.gotStr) {
		t.Errorf("%s: setter.gotStr = %v, want %v", "SetStore received wrong store", setter.gotStr, Store(st))
	}
	if !reflect.DeepEqual(DNSSECCryptoLimiter(limiter), setter.gotLim) {
		t.Errorf("%s: setter.gotLim = %v, want %v", "crypto limiter was not shared", setter.gotLim, DNSSECCryptoLimiter(limiter))
	}
}

// TestAutoWire_MultipleProviders covers the first-wins branch plus
// the multi-provider warning log.
func TestAutoWire_MultipleProviders(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	first := &providerHandler{n: "cacheA", store: nopStore{}}
	second := &providerHandler{n: "cacheB", store: nopStore{}}
	setter := &setterHandler{n: "resolver"}

	Register("cacheA", func(*config.Config) Handler { return first })
	Register("cacheB", func(*config.Config) Handler { return second })
	Register("resolver", func(*config.Config) Handler { return setter })

	Setup(&config.Config{})

	// First-wins: setter's store must be from the first provider.
	if !reflect.DeepEqual(first.store, setter.gotStr) {
		t.Errorf("setter.gotStr = %v, want %v", setter.gotStr, first.store)
	}
}

func TestAutoWire_TypedNilCryptoProviderDoesNotMaskUsableProvider(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	var unavailable *typedNilCryptoLimiter
	usable := nopCryptoLimiter{}
	first := &providerHandler{n: "resolverA", limiter: unavailable}
	second := &providerHandler{n: "resolverB", limiter: usable}
	setter := &setterHandler{n: "cache"}

	Register("resolverA", func(*config.Config) Handler { return first })
	Register("resolverB", func(*config.Config) Handler { return second })
	Register("cache", func(*config.Config) Handler { return setter })

	Setup(&config.Config{})

	if !reflect.DeepEqual(DNSSECCryptoLimiter(usable), setter.gotLim) {
		t.Errorf("setter.gotLim = %v, want %v", setter.gotLim, DNSSECCryptoLimiter(usable))
	}
}

// TestAutoWire_SetterWithoutProvider covers the
// "StoreSetter present but no StoreProvider" warning path — the
// setter's store stays nil (no store wired).
func TestAutoWire_SetterWithoutProvider(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	setter := &setterHandler{n: "resolver"}
	Register("resolver", func(*config.Config) Handler { return setter })

	Setup(&config.Config{})

	if setter.gotStr != nil {
		t.Errorf("%s: setter.gotStr = %v, want nil", "SetStore must not be called without a StoreProvider", setter.gotStr)
	}
	// But queryer setters still fire.
	if setter.gotQ == nil {
		t.Fatalf("setter.gotQ is nil")
	}
	if setter.gotPQ == nil {
		t.Fatalf("setter.gotPQ is nil")
	}
}

// TestPutChain_NilSafe covers the early-return path on nil
// Pipeline / nil Chain in PutChain.
func TestPutChain_NilSafe(t *testing.T) {
	var p *Pipeline
	p.PutChain(nil) // must not panic

	Reset()
	t.Cleanup(Reset)
	Register("h", func(*config.Config) Handler { return &namedHandler{n: "h"} })
	Setup(&config.Config{})
	GlobalPipeline().PutChain(nil) // nil chain must not panic either
}
