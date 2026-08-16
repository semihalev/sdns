package middleware

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
)

// TestDetachPropagatesCancellation pins the one context semantic that
// crosses the strict-detach boundary: a middleware that wrapped the
// strict context with its own cancel must still stop the slow work the
// detached context now runs. (Custom context values deliberately do not
// cross — the carrier under the original context is recycled with the
// job, and background work outlives it.)
func TestDetachPropagatesCancellation(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	ch := NewChain(nil)
	ch.Reset(mock.NewWriter("udp", "127.0.0.1:0"), req)

	outer, cancel := context.WithCancel(context.Background())
	detached, cleanup := ch.detachStrictContext(outer)
	defer cleanup()

	select {
	case <-detached.Done():
		t.Fatal("detached context born canceled")
	default:
	}

	cancel()
	select {
	case <-detached.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("outer cancellation never reached the detached context")
	}

	// A parent that can never cancel — the job carrier's shape — must
	// leave the detached context alone.
	quiet, quietCleanup := ch.detachStrictContext(context.Background())
	defer quietCleanup()
	select {
	case <-quiet.Done():
		t.Fatal("uncancelable parent canceled the detached context")
	default:
	}
}
