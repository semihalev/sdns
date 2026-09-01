package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/semihalev/sdns/internal/contextutil"
	"github.com/semihalev/sdns/internal/mock"
)

// TestEnsureRecursionWorkOffPolicyLeavesPendingPin pins the
// recursion_firewall mode="off" miss shape: the chain plants the pending
// pin unconditionally, and the resolver still calls EnsureRecursionWork
// with its (disabled) policy. The transition must leave the pin pending,
// materializing returns nil for a disabled policy, and a typed-nil ledger
// written into the pin slot is a panic for the next reader (the second
// ensure, or finishLazyRecursionWork when the request unwinds).
func TestEnsureRecursionWorkOffPolicyLeavesPendingPin(t *testing.T) {
	offPolicy := RecursionWorkPolicy{Mode: RecursionWorkOff}
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, ch *Chain) {
		// The resolver's ensure on a recursive miss with the firewall off.
		_, ledger := EnsureRecursionWork(ctx, offPolicy)
		if ledger != nil {
			t.Errorf("disabled policy materialized a ledger: %+v", ledger)
		}
		// The next reader walks the pinned path again; a typed-nil pin
		// panics here.
		_, ledger = EnsureRecursionWork(ctx, offPolicy)
		if ledger != nil {
			t.Errorf("second ensure materialized a ledger: %+v", ledger)
		}
		if err := DebitRecursionWork(ctx, RecursionWorkOutboundQuery); err != nil {
			t.Errorf("debit with the firewall off: %v", err)
		}
		ch.Cancel()
	})}, offPolicy)
	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())

	ctx := contextutil.WithLazyTimeout(context.Background(), time.Minute)
	defer ctx.Cancel()
	// Chain unwind runs finishLazyRecursionWork over the pin; a typed-nil
	// there panics before Next returns.
	ch.Next(ctx)
}
