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
	// Only the packaged copy: the repository root's sdns.conf is
	// gitignored, it is a user's live config, not ours to write.
	generated := fmt.Sprintf(defaultConfig, configver)
	if err := os.WriteFile("../contrib/linux/sdns.conf", []byte(generated), 0o644); err != nil { //nolint:gosec // repo fixture
		t.Fatal(err)
	}
}
