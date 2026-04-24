package dnstap

import (
	"testing"
)

// TestClientOnly pins Dnstap's self-declared ClientOnly() == true so
// middleware.autoWire excludes it from internal sub-pipelines.
// In-package test so coverage registers on the dnstap binary, not
// on the cross-package test under middleware/. New() may return
// typed-nil on missing config, so we exercise the method on a
// concrete zero value instead of depending on constructor shape.
func TestClientOnly(t *testing.T) {
	var d *Dnstap
	if !d.ClientOnly() {
		t.Fatal("Dnstap.ClientOnly() = false, want true")
	}
}
