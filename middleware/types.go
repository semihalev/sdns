package middleware

import (
	"context"
	"reflect"

	"github.com/semihalev/sdns/config"
)

// Handler is the middleware interface. Implementations must be safe for
// concurrent use.
type Handler interface {
	// Name returns the middleware name. It must match the name used in
	// Register so Pipeline.Get can resolve the handler back.
	Name() string

	// ServeDNS processes a DNS query. A handler is expected to call
	// ch.Next to continue the chain, or ch.Cancel / ch.CancelWithRcode
	// to stop it.
	ServeDNS(ctx context.Context, ch *Chain)
}

// Constructor builds a Handler from config. A Constructor that returns a
// typed-nil pointer (e.g. `(*Reflex)(nil)`) signals that the middleware is
// disabled for this config and is skipped at Build time.
type Constructor func(*config.Config) Handler

// HandlerFunc adapts a plain function into a Handler. Handy in tests that
// want to inject a one-off behaviour without declaring a new type.
type HandlerFunc func(context.Context, *Chain)

// Name returns the fixed label "HandlerFunc".
func (f HandlerFunc) Name() string { return "HandlerFunc" }

// ServeDNS dispatches to f.
func (f HandlerFunc) ServeDNS(ctx context.Context, ch *Chain) { f(ctx, ch) }

// isNilHandler reports whether a Constructor result represents a disabled
// middleware. A typed-nil pointer wrapped in an interface has a non-nil itab
// but a nil underlying value, so a plain `h == nil` misses it. Catch both
// the untyped-nil and typed-nil cases so Constructors can keep their
// existing "return nil when disabled" idiom.
func isNilHandler(h Handler) bool {
	if h == nil {
		return true
	}
	v := reflect.ValueOf(h)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Chan, reflect.Map, reflect.Slice, reflect.Func:
		return v.IsNil()
	}
	return false
}
