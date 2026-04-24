package reflex

import (
	"testing"

	"github.com/semihalev/sdns/config"
)

// TestClientOnly pins Reflex's ClientOnly() == true so
// middleware.autoWire keeps it out of internal sub-pipelines —
// amplification-detection heuristics don't apply to sub-queries.
func TestClientOnly(t *testing.T) {
	r := New(&config.Config{})
	if r == nil {
		return
	}
	if !r.ClientOnly() {
		t.Fatal("Reflex.ClientOnly() = false, want true")
	}
}
