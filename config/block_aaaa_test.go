package config

import (
	"fmt"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestBlockAAAADefaultAndParsing(t *testing.T) {
	for _, tc := range []struct {
		name, input string
		want        bool
	}{
		{"omitted", "", false},
		{"false", "block_aaaa = false", false},
		{"true", "block_aaaa = true", true},
		{"dns64 coexistence", "block_aaaa = true\n[dns64]\nenabled = true", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var cfg Config
			md, err := toml.Decode(tc.input, &cfg)
			if err != nil {
				t.Fatal(err)
			}
			if len(md.Undecoded()) != 0 {
				t.Fatalf("unrecognized keys: %v", md.Undecoded())
			}
			if cfg.BlockAAAA != tc.want {
				t.Fatalf("BlockAAAA = %v, want %v", cfg.BlockAAAA, tc.want)
			}
		})
	}
	generated := fmt.Sprintf(defaultConfig, configver)
	if !strings.Contains(generated, "block_aaaa = false") {
		t.Fatal("generated default omits block_aaaa = false")
	}
	var cfg Config
	if _, err := toml.Decode(generated, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.BlockAAAA {
		t.Fatal("generated default enables suppression")
	}
}

// TestBlockAAAADNS64Coexistence pins precedence as a runtime policy:
// configuring both is accepted rather than refused by the config gate.
func TestBlockAAAADNS64Coexistence(t *testing.T) {
	cfg := &Config{BlockAAAA: true, DNS64: DNS64Config{Enabled: true}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected AAAA suppression with DNS64: %v", err)
	}
}
