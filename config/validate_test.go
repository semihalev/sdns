package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
		// The access list is parsed with netip.ParsePrefix alone, so a bare
		// address is dropped at startup — and if it is the only entry the
		// allow set ends up empty, blocking every client.
		{"accesslist bare IP", Config{AccessList: []string{"192.0.2.1"}}, "accesslist"},
		// Documented for years, never implemented: startup rejects it.
		{"crit log level", Config{LogLevel: "crit"}, "loglevel"},
		{"root server family", Config{RootServers: []string{"[2001:db8::1]:53"}}, "rootservers"},
		{"root6 server family", Config{Root6Servers: []string{"192.0.2.1:53"}}, "root6servers"},
		{"root key not a KSK", Config{RootKeys: []string{
			". 172800 IN DNSKEY 256 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
		}}, "key-signing key"},
		{"root key wrong owner", Config{RootKeys: []string{
			"example. 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
		}}, "root zone"},
		// /49 is a valid IPv6 CIDR and an invalid Pref64: the runtime drops
		// it and falls back to 64:ff9b::/96, sending traffic somewhere else
		// entirely than the file says.
		{"dns64 prefix length", Config{DNS64: DNS64Config{Prefixes: []string{"2001:db8::/49"}}}, "dns64 prefix"},
		// Byte 8 is the high half of the fifth group, inside a /96.
		{"dns64 reserved byte", Config{DNS64: DNS64Config{Prefixes: []string{"2001:db8:0:0:ff00::/96"}}}, "byte 8"},
		// 91-100 passed before and then silently disabled prefetch.
		{"prefetch above the cache ceiling", Config{Prefetch: 95}, "prefetch"},
		{"root server", Config{RootServers: []string{"hello world"}}, "rootservers"},
		{"root server without port", Config{RootServers: []string{"192.0.2.1"}}, "rootservers"},
		{"forwarder upstream", Config{ForwarderServers: []string{"nonsense"}}, "forwarderservers"},
		{"DoT needs an IP", Config{ForwarderServers: []string{"tls://dns.example.com:853"}}, "forwarderservers"},
		{"forward zone upstream", Config{ForwardZones: []ForwardZoneConfig{
			{Name: "corp.example.", Servers: []string{"nonsense"}},
		}}, "forward_zone"},
		{"negative size", Config{CacheSize: -1}, "cachesize"},
		// A bad anchor is fatal at resolver construction, so -t passing here
		// meant the server then refused to start.
		{"root key", Config{RootKeys: []string{"this is not a DNSKEY"}}, "rootkeys"},
		{"root key wrong type", Config{RootKeys: []string{". 172800 IN A 192.0.2.1"}}, "rootkeys"},
		{"outbound family", Config{OutboundIPs: []string{"2001:db8::1"}}, "outboundips"},
		{"api address", Config{API: "not an address"}, "api"},
		{"hyperlocal source", Config{HyperlocalRootSources: []string{"no-port"}}, "hyperlocal_root_sources"},
		// Out of range is silently replaced by the default, so the operator
		// believes they set a threshold they did not.
		{"reflex threshold", Config{ReflexThreshold: 42}, "reflexthreshold"},
		{"prefetch percentage", Config{Prefetch: 250}, "prefetch"},
		{"view network", Config{Views: []ViewConfig{{Zone: "a.", Networks: []string{"nope"}}}}, "network"},
		{"view answer", Config{Views: []ViewConfig{{Zone: "a.", Answers: []string{"not an rr"}}}}, "answer"},
		{"dns64 prefix", Config{DNS64: DNS64Config{Prefixes: []string{"192.0.2.0/24"}}}, "dns64 prefix"},
		{"ecs scope", Config{ECS: ECSConfig{ForwardV4Max: 33}}, "ecs forward_v4"},
		{"blocklist url", Config{BlockLists: []string{"not-a-url"}}, "blocklists"},
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
		AccessList:       []string{"0.0.0.0/0", "::0/0", "192.0.2.1/32"},
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
	body := fmt.Sprintf(
		"version = %q\ndirectory = %q\nforwardservers = [\"1.1.1.1:53\"]\nmaxdepth_old = 30\n",
		configver, filepath.Join(dir, "db"),
	)
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
	body := fmt.Sprintf(
		"version = %q\ndirectory = %q\nnullroute = \"not-an-ip\"\n",
		configver, filepath.Join(dir, "db"),
	)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(path, "test"); err == nil {
		t.Fatal("Load() accepted a config with an unusable value")
	} else if !strings.Contains(err.Error(), "nullroute") {
		t.Fatalf("Load() = %v, want the problem to name nullroute", err)
	}
}

// TestValidateReportsAcrossFormerlySeparateChecks pins the promise the README
// makes. These four used to return one at a time from the load path, so a file
// with several mistakes took several runs to fix.
func TestValidateReportsAcrossFormerlySeparateChecks(t *testing.T) {
	cfg := &Config{
		DNSSEC:       "maybe",
		ForwardZones: []ForwardZoneConfig{{Name: "corp.example."}},
	}
	cfg.RecursionFirewall.Mode = "sideways"
	cfg.ServeStaleMaxTTL.Duration = -time.Second

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() accepted four broken settings")
	}
	for _, want := range []string{
		"dnssec", "forward_zone", "recursion firewall", "serve_stale_max_ttl",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v\nmissing a problem for %q", err, want)
		}
	}
}

// TestValidateLeavesViewZoneAlone pins that the view label is not judged as a
// domain name. The middleware only carries it into log lines, so validating it
// would stop the server on upgrade for labels that work today.
func TestValidateLeavesViewZoneAlone(t *testing.T) {
	cfg := &Config{Views: []ViewConfig{{
		Zone:     "office clients (floor 3)",
		Networks: []string{"192.0.2.0/24"},
		Answers:  []string{"printer.local. 300 IN A 192.0.2.10"},
	}}}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() rejected a free-form view label: %v", err)
	}
}

func TestValidateFamilySpecificLists(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want string
	}{
		// The runtime keeps these by mask length and drops the wrong family
		// with a log line, so the exclusion quietly does not apply.
		{"exclude_a takes IPv4", Config{DNS64: DNS64Config{
			ExcludeANetworks: []string{"2001:db8::/32"},
		}}, "exclude_a_networks"},
		{"exclude_aaaa takes IPv6", Config{DNS64: DNS64Config{
			ExcludeAAAANetworks: []string{"192.0.2.0/24"},
		}}, "exclude_aaaa_networks"},
		// The updater fetches with an http.Client, so anything else never loads.
		{"blocklist scheme", Config{BlockLists: []string{"ftp://example.com/list"}}, "http"},
		{"negative tcp pool", Config{TCPMaxConnections: -1}, "tcpmaxconnections"},
		{"negative dnstap interval", Config{DnstapFlushInterval: -1}, "dnstapflushinterval"},
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

	// Both families are legal where the runtime accepts either.
	both := &Config{DNS64: DNS64Config{ClientNetworks: []string{"192.0.2.0/24", "2001:db8::/32"}}}
	if err := both.Validate(); err != nil {
		t.Fatalf("Validate() rejected a mixed-family client_networks list: %v", err)
	}
}

func TestValidateNegativeECSCacheLimit(t *testing.T) {
	cfg := &Config{}
	cfg.ECS.CacheLimitTTL.Duration = -time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cache_limit_ttl") {
		t.Fatalf("Validate() = %v, want the negative ECS cache limit rejected", err)
	}
}

// TestValidateRootKeyAlgorithm pins that an anchor the verifier cannot use is
// caught here. Nothing downstream rejects it: NewResolver only fails on a
// record that will not parse, so an anchor like this loads and then silently
// fails every signature it is asked to verify.
func TestValidateRootKeyAlgorithm(t *testing.T) {
	const material = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"

	for _, tc := range []struct {
		name string
		alg  string
		want bool
	}{
		{"DSA is gone from the library", "3", false},
		{"ECC-GOST is gone too", "12", false},
		{"unassigned codepoint", "200", false},
		// Asked of the library, not assumed: ED448 has a name and a number
		// and still cannot be verified with.
		{"ED448 has a name but no verifier", "16", false},
		{"RSASHA256 is what the root uses", "8", true},
		{"ECDSAP256SHA256 is the successor", "13", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{RootKeys: []string{
				". 172800 IN DNSKEY 257 3 " + tc.alg + " " + material,
			}}
			err := cfg.Validate()
			usable := err == nil
			if usable != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", usable, tc.want, err)
			}
			if !tc.want && !strings.Contains(err.Error(), "cannot be verified with") {
				t.Fatalf("Validate() = %v, want the algorithm named as the problem", err)
			}
		})
	}
}

// TestLoadReportsUnknownKeysAlongsideValueProblems pins the second half of the
// one-pass promise. The keys are recorded before the gate, but Load returns no
// Config when validation fails — so without this they reached the operator
// only as a log line, and fixing the value meant a second run to discover the
// key.
func TestLoadReportsUnknownKeysAlongsideValueProblems(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf(
		"version = %q\ndirectory = %q\nnullroute = \"not-an-ip\"\nmaxdepth_old = 30\n",
		configver, filepath.Join(dir, "db"),
	)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := Load(path, "test")
	if err == nil {
		t.Fatal("Load() accepted a config with an unusable value")
	}
	for _, want := range []string{"nullroute", "maxdepth_old"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Load() = %v\nmissing %q — the operator would need a second run", err, want)
		}
	}
}
