package config

import (
	"fmt"
	"os"
	"testing"
)

// TestDumpDefaultConfig regenerates the packaged default when asked to:
// SDNS_REGEN_CONFIG names the destination. It exists so a template change
// updates contrib/linux/sdns.conf with the exact bytes
// TestPackagedConfigMatchesGeneratedDefault compares.
func TestDumpDefaultConfig(t *testing.T) {
	dest := os.Getenv("SDNS_REGEN_CONFIG")
	if dest == "" {
		t.Skip("set SDNS_REGEN_CONFIG to a path to regenerate")
	}
	if err := os.WriteFile(dest, fmt.Appendf(nil, defaultConfig, configver), 0o600); err != nil { //nolint:gosec // G703 - dev-only regen helper, path chosen by the developer running it
		t.Fatal(err)
	}
}
