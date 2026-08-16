package config

import (
	"fmt"
	"os"
	"testing"
)

// TestWriteGeneratedDefault regenerates the packaged example configs from
// the template when asked to, so they can never drift by hand-editing.
// Run with: go test -run TestWriteGeneratedDefault -args -write ./config/
func TestWriteGeneratedDefault(t *testing.T) {
	if os.Getenv("SDNS_WRITE_CONFIG") == "" {
		t.Skip("set SDNS_WRITE_CONFIG=1 to regenerate the packaged configs")
	}
	generated := fmt.Sprintf(defaultConfig, configver)
	for _, path := range []string{"../sdns.conf", "../contrib/linux/sdns.conf"} {
		if err := os.WriteFile(path, []byte(generated), 0o644); err != nil { //nolint:gosec // repo fixture
			t.Fatal(err)
		}
	}
}
