package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRejectsUnusableValues(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		// "maybe" used to become "on": a typo silently switched validation
		// on when the operator meant to switch it off.
		{"dnssec enum", Config{DNSSEC: "maybe"}, "dnssec"},
		{"log level", Config{LogLevel: "verbose"}, "loglevel"},
		{"bind address", Config{Bind: "not an address"}, "bind"},
		{"nullroute", Config{Nullroute: "not-an-ip"}, "nullroute"},
		{"accesslist", Config{AccessList: []string{"999.999.999.999/99"}}, "accesslist"},
		{"root server", Config{RootServers: []string{"hello world"}}, "rootservers"},
		{"root server without port", Config{RootServers: []string{"192.0.2.1"}}, "rootservers"},
		{"forwarder upstream", Config{ForwarderServers: []string{"nonsense"}}, "forwarderservers"},
		{"DoT needs an IP", Config{ForwarderServers: []string{"tls://dns.example.com:853"}}, "forwarderservers"},
		{"forward zone upstream", Config{ForwardZones: []ForwardZoneConfig{
			{Name: "corp.example.", Servers: []string{"nonsense"}},
		}}, "forward_zone"},
		{"negative size", Config{CacheSize: -1}, "cachesize"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Fatalf("Validate() accepted %+v", tc.cfg)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want a problem naming %q", err, tc.want)
			}
		})
	}
}

func TestValidateAcceptsUsableValues(t *testing.T) {
	cfg := Config{
		DNSSEC:           "on",
		LogLevel:         "info",
		Bind:             ":53",
		Nullroute:        "0.0.0.0",
		Nullroutev6:      "::0",
		AccessList:       []string{"0.0.0.0/0", "::0/0", "192.0.2.1"},
		RootServers:      []string{"192.5.5.241:53"},
		Root6Servers:     []string{"[2001:500:2f::f]:53"},
		ForwarderServers: []string{"1.1.1.1:53", "tls://1.1.1.1:853", "https://cloudflare-dns.com/dns-query"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected a usable configuration: %v", err)
	}
}

// TestValidateReportsEveryProblem pins the whole-list behaviour: an operator
// fixing a file wants every problem at once, not one per run.
func TestValidateReportsEveryProblem(t *testing.T) {
	err := (&Config{
		DNSSEC:    "maybe",
		Bind:      "nope",
		Nullroute: "also-nope",
	}).Validate()
	if err == nil {
		t.Fatal("Validate() accepted three broken settings")
	}
	for _, want := range []string{"dnssec", "bind", "nullroute"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v, missing a problem for %q", err, want)
		}
	}
}

// TestLoadRecordsUndecodedKeys pins the upgrade path: a key this version no
// longer has, or a typo, takes no effect and must be reported rather than
// silently ignored. Load only records it — refusing to start over a stale key
// would turn an upgrade into an outage — and `sdns -t` fails on it.
func TestLoadRecordsUndecodedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := "version = \"" + configver + "\"\n" +
		"directory = \"" + filepath.Join(dir, "db") + "\"\n" +
		"forwardservers = [\"1.1.1.1:53\"]\n" +
		"maxdepth_old = 30\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path, "test")
	if err != nil {
		t.Fatalf("Load() failed on a config whose values are all usable: %v", err)
	}
	got := strings.Join(cfg.UndecodedKeys(), ",")
	for _, want := range []string{"forwardservers", "maxdepth_old"} {
		if !strings.Contains(got, want) {
			t.Fatalf("UndecodedKeys() = %q, missing %q", got, want)
		}
	}
}

// TestLoadRejectsUnusableValues pins that Validate is actually wired into the
// load path. Without this, the checks could be correct and never run.
func TestLoadRejectsUnusableValues(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := "version = \"" + configver + "\"\n" +
		"directory = \"" + filepath.Join(dir, "db") + "\"\n" +
		"nullroute = \"not-an-ip\"\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path, "test"); err == nil {
		t.Fatal("Load() accepted a config with an unusable value")
	} else if !strings.Contains(err.Error(), "nullroute") {
		t.Fatalf("Load() = %v, want the problem to name nullroute", err)
	}
}
