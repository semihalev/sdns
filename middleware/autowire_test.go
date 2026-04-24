package middleware

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
)

// providerHandler implements Handler + StoreProvider (+ optional
// extra roles via embedded bool flags).
type providerHandler struct {
	n     string
	store Store
}

func (h *providerHandler) Name() string                            { return h.n }
func (h *providerHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *providerHandler) Store() Store                            { return h.store }

// setterHandler implements QueryerSetter, PrefetchQueryerSetter,
// and StoreSetter — used to pin that autoWire invokes all three.
type setterHandler struct {
	n      string
	gotQ   Queryer
	gotPQ  Queryer
	gotStr Store
}

func (h *setterHandler) Name() string                            { return h.n }
func (h *setterHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *setterHandler) SetQueryer(q Queryer)                    { h.gotQ = q }
func (h *setterHandler) SetPrefetchQueryer(q Queryer)            { h.gotPQ = q }
func (h *setterHandler) SetStore(s Store)                        { h.gotStr = s }

// clientOnlyHandler reports ClientOnly()==true; autoWire must
// exclude it from both queryerSub and prefetchSub.
type clientOnlyHandler struct{ n string }

func (h *clientOnlyHandler) Name() string                            { return h.n }
func (h *clientOnlyHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *clientOnlyHandler) ClientOnly() bool                        { return true }

// nopStore implements Store.
type nopStore struct{}

func (nopStore) Get(*dns.Msg) (*dns.Msg, bool)  { return nil, false }
func (nopStore) SetFromResponse(*dns.Msg, bool) {}

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
	prov := &providerHandler{n: "cache", store: st}
	setter := &setterHandler{n: "resolver"}
	co := &clientOnlyHandler{n: "metrics"}

	Register("metrics", func(*config.Config) Handler { return co })
	Register("cache", func(*config.Config) Handler { return prov })
	Register("resolver", func(*config.Config) Handler { return setter })

	Setup(&config.Config{})

	// metrics is ClientOnly → must be missing from both sub-pipelines.
	pipe := GlobalPipeline()
	sub := pipe.SubPipeline("metrics")
	assert.Nil(t, sub.Get("metrics"))

	// Setter got all three wiring calls.
	assert.NotNil(t, setter.gotQ, "SetQueryer not called")
	assert.NotNil(t, setter.gotPQ, "SetPrefetchQueryer not called")
	assert.Equal(t, Store(st), setter.gotStr, "SetStore received wrong store")
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
	assert.Equal(t, first.store, setter.gotStr)
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

	assert.Nil(t, setter.gotStr, "SetStore must not be called without a StoreProvider")
	// But queryer setters still fire.
	assert.NotNil(t, setter.gotQ)
	assert.NotNil(t, setter.gotPQ)
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
