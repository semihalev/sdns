package middleware_test

import (
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/accesslist"
	"github.com/semihalev/sdns/middleware/accesslog"
	"github.com/semihalev/sdns/middleware/dnstap"
	"github.com/semihalev/sdns/middleware/metrics"
	"github.com/semihalev/sdns/middleware/ratelimit"
	"github.com/semihalev/sdns/middleware/reflex"
)

// TestClientOnlyMarkers pins the middlewares that self-declare as
// client-only (excluded from the internal sub-pipeline built by
// autoWire). Any middleware added to this list becomes a candidate
// for filtering; any removed from the list silently starts running
// on internal traffic. Test exists to catch accidental drops.
func TestClientOnlyMarkers(t *testing.T) {
	cfg := &config.Config{}

	cases := []struct {
		name string
		h    middleware.Handler
	}{
		{"metrics", metrics.New(cfg)},
		{"dnstap", dnstap.New(cfg)},
		{"accesslog", accesslog.New(cfg)},
		{"ratelimit", ratelimit.New(cfg)},
		{"accesslist", accesslist.New(cfg)},
		{"reflex", reflex.New(cfg)},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			co, ok := c.h.(middleware.ClientOnly)
			if !ok {
				t.Fatalf("%s must implement middleware.ClientOnly", c.name)
			}
			if !co.ClientOnly() {
				t.Fatalf("%s.ClientOnly() = false, want true (client-guard middleware)", c.name)
			}
		})
	}
}
