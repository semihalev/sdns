package middleware

import (
	"context"

	"github.com/semihalev/sdns/internal/contextutil"
)

// clientECSContextKey tags a request tree whose original client query carried
// an EDNS Client Subnet option. The marker is intentionally independent of
// the EDNS forwarding policy: the EDNS middleware may strip ECS before later
// middleware sees the message, while security-sensitive shared state still
// needs to remember that the request was audience-scoped.
type clientECSContextKey struct{}

var clientECSKey = &clientECSContextKey{}

// MarkClientECS returns a context that records that the original client query
// carried EDNS Client Subnet. It is idempotent so nested pipelines can preserve
// the marker without adding another context node. The marker is a scalar and
// request-lifetime, so it pins to the carrier when one exists; a foreign
// context gets a value node as before.
func MarkClientECS(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	if HasClientECS(ctx) {
		return ctx
	}
	if contextutil.TryPinValue(ctx, clientECSKey, true) {
		return ctx
	}
	return context.WithValue(ctx, clientECSKey, struct{}{})
}

// HasClientECS reports whether the original client query carried EDNS Client
// Subnet, even if an earlier middleware stripped the option from the message.
func HasClientECS(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	if _, ok := contextutil.PinnedValue(ctx, clientECSKey); ok {
		return true
	}
	return ctx.Value(clientECSKey) != nil
}
