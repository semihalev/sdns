package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rpzZoneFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.zone")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

const validRPZZone = `
rpz.test. IN SOA ns.rpz.test. admin.rpz.test. 1 3600 900 604800 300
bad.example.com.rpz.test. IN CNAME .
`

func rpzConfig(zones ...RPZZone) *Config {
	c := new(Config)
	c.RPZ = RPZ{Enabled: true, Mode: "shadow", Zones: zones}
	return c
}

func wantRPZProblem(t *testing.T, c *Config, fragment string) {
	t.Helper()
	err := c.Validate()
	if err == nil {
		t.Fatalf("Validate accepted a config that should fail on %q", fragment)
	}
	if !strings.Contains(err.Error(), fragment) {
		t.Fatalf("Validate error %q does not name %q", err, fragment)
	}
}

func TestValidateRPZ(t *testing.T) {
	good := rpzZoneFile(t, validRPZZone)

	t.Run("valid config passes", func(t *testing.T) {
		if err := rpzConfig(RPZZone{Name: "feed", File: good}).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("disabled section is never judged", func(t *testing.T) {
		c := new(Config)
		c.RPZ = RPZ{Enabled: false, Mode: "bogus", Zones: []RPZZone{{Name: "", File: "/does/not/exist"}}}
		if err := c.Validate(); err != nil {
			t.Fatalf("a disabled rpz block must not be validated: %v", err)
		}
	})

	t.Run("bad mode", func(t *testing.T) {
		c := rpzConfig(RPZZone{Name: "feed", File: good})
		c.RPZ.Mode = "enfroce"
		wantRPZProblem(t, c, "rpz.mode")
	})

	t.Run("enabled without zones", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(), "lists no zones")
	})

	t.Run("too many zones", func(t *testing.T) {
		zones := make([]RPZZone, 65)
		for i := range zones {
			zones[i] = RPZZone{Name: "z", File: good}
		}
		wantRPZProblem(t, rpzConfig(zones...), "at most 64")
	})

	t.Run("missing and duplicate names", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{File: good}), "name is required")
		wantRPZProblem(t, rpzConfig(
			RPZZone{Name: "feed", File: good},
			RPZZone{Name: "feed", File: good},
		), "already used")
	})

	t.Run("bad policy", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Policy: "blockhard"}), "policy")
	})

	t.Run("cname target rules", func(t *testing.T) {
		// Required exactly when the policy is cname...
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Policy: "cname"}), "needs a cname target")
		// ...must be an FQDN there...
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Policy: "cname", Cname: "garden.example"}), "fully qualified")
		// ...and is refused anywhere else, where the runtime would
		// silently ignore it.
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Policy: "given", Cname: "garden.example."}), "only read with")
		// The valid shape passes.
		if err := rpzConfig(RPZZone{Name: "feed", File: good, Policy: "cname", Cname: "garden.example."}).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("file judged with the runtime's parser", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed"}), "either file or source is required")
		// The OS names the missing file differently per platform ("no
		// such file" vs "cannot find the file"), so the assertion holds
		// onto the one part we control: the path in the error.
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: filepath.Join(t.TempDir(), "absent.zone")}), "absent.zone")

		noSOA := rpzZoneFile(t, "bad.example.com.rpz.test. IN CNAME .\n")
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: noSOA}), "no SOA")

		// A zone that parses but compiles nothing would filter nothing —
		// which is never what an operator enabling RPZ meant.
		empty := rpzZoneFile(t, "rpz.test. IN SOA ns. admin. 1 3600 900 604800 300\n")
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: empty}), "compiled no rules")
	})
}

func TestValidateRPZSourceZones(t *testing.T) {
	good := rpzZoneFile(t, validRPZZone)

	t.Run("valid source zone passes", func(t *testing.T) {
		c := rpzConfig(RPZZone{Name: "feed", Source: "203.0.113.5:53", Origin: "rpz.vendor.example."})
		if err := c.Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("file and source are exclusive", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Source: "203.0.113.5:53", Origin: "z."}), "fed one way")
	})

	t.Run("source needs a well-formed address and origin", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", Source: "203.0.113.5", Origin: "z."}), "host:port")
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", Source: "203.0.113.5:53"}), "needs an origin")
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", Source: "203.0.113.5:53", Origin: "no-dot.example"}), "fully qualified")
	})

	t.Run("tsig shape judged with the runtime's parser", func(t *testing.T) {
		base := RPZZone{Name: "feed", Source: "203.0.113.5:53", Origin: "z."}
		bad := base
		bad.TsigKey = "just-a-name"
		wantRPZProblem(t, rpzConfig(bad), "tsig_key")
		notB64 := base
		notB64.TsigKey = "k.:hmac-sha256.:not!!base64"
		wantRPZProblem(t, rpzConfig(notB64), "base64")
		// An algorithm the dns library cannot sign with must be refused
		// here, not discovered at runtime as a feed that never transfers.
		badAlgo := base
		badAlgo.TsigKey = "k.:hmac-sha999.:c2VjcmV0"
		wantRPZProblem(t, rpzConfig(badAlgo), "algorithm")
		ok := base
		ok.TsigKey = "k.:hmac-sha256.:c2VjcmV0"
		if err := rpzConfig(ok).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("origin and tsig are refused on file zones", func(t *testing.T) {
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, Origin: "z."}), "file-fed")
		wantRPZProblem(t, rpzConfig(RPZZone{Name: "feed", File: good, TsigKey: "k.:a.:YQ=="}), "only transfers are signed")
	})
}
