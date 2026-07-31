// Package contextutil provides context lifecycle helpers shared by transports
// and middleware.
package contextutil

import (
	"context"
	"time"
)

// EffectiveError reports a context cancellation even at the narrow deadline
// boundary where the wall clock has reached Deadline but the context timer
// goroutine has not yet published Err. This matters after a socket operation:
// the kernel deadline can return first, and treating that I/O timeout as
// upstream evidence would leak a request-local failure into shared state.
func EffectiveError(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	now := time.Now()
	if !now.Before(deadline) {
		return context.DeadlineExceeded
	}
	return nil
}
