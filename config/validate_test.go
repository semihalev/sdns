package config

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testP256 is a generated ECDSAP256SHA256 public key, used wherever a test
// needs an anchor that is actually usable rather than merely well-formed.
const testP256 = "FS/jjwld5fQ2hD31w4Odohy65Je3eGSYDvJgKO0qBBEFRC5fa6GvcWdLyn0sj49unyBRv3nAHAH0UtAyYLZi7w=="

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
		{"root6 server family", Config{IPv6Access: true, Root6Servers: []string{"192.0.2.1:53"}}, "root6servers"},
		{"root key not a KSK", Config{DNSSEC: "on", RootKeys: []string{
			". 172800 IN DNSKEY 256 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
		}}, "key-signing key"},
		{"root key wrong owner", Config{DNSSEC: "on", RootKeys: []string{
			"example. 172800 IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3",
		}}, "root zone"},
		// /49 is a valid IPv6 CIDR and an invalid Pref64: the runtime drops
		// it and falls back to 64:ff9b::/96, sending traffic somewhere else
		// entirely than the file says.
		{"dns64 prefix length", Config{DNS64: DNS64Config{Enabled: true, Prefixes: []string{"2001:db8::/49"}}}, "dns64 prefix"},
		// Byte 8 is the high half of the fifth group, inside a /96.
		{"dns64 reserved byte", Config{DNS64: DNS64Config{Enabled: true, Prefixes: []string{"2001:db8:0:0:ff00::/96"}}}, "byte 8"},
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
		{"root key wrong type", Config{DNSSEC: "on", RootKeys: []string{". 172800 IN A 192.0.2.1"}}, "rootkeys"},
		{"outbound family", Config{OutboundIPs: []string{"2001:db8::1"}}, "outboundips"},
		{"api address", Config{API: "not an address"}, "api"},
		{"hyperlocal source", Config{HyperlocalRoot: true, HyperlocalRootSources: []string{"no-port"}}, "hyperlocal_root_sources"},
		// Out of range is silently replaced by the default, so the operator
		// believes they set a threshold they did not.
		{"reflex threshold", Config{ReflexEnabled: true, ReflexThreshold: 42}, "reflexthreshold"},
		{"prefetch percentage", Config{Prefetch: 250}, "prefetch"},
		{"view network", Config{Views: []ViewConfig{{Zone: "a.", Networks: []string{"nope"}}}}, "network"},
		{"view answer", Config{Views: []ViewConfig{{Zone: "a.", Answers: []string{"not an rr"}}}}, "answer"},
		{"dns64 prefix", Config{DNS64: DNS64Config{Enabled: true, Prefixes: []string{"192.0.2.0/24"}}}, "dns64 prefix"},
		{"ecs scope", Config{ECS: ECSConfig{Enabled: true, ForwardV4Max: 33}}, "ecs forward_v4"},
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
		"version = %q\ndirectory = %q\ndnssec = \"off\"\nrootservers = [\"192.5.5.241:53\"]\nforwardservers = [\"1.1.1.1:53\"]\nmaxdepth_old = 30\n",
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
		"version = %q\ndirectory = %q\nrootservers = [\"192.5.5.241:53\"]\nnullroute = \"not-an-ip\"\n",
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
			Enabled:          true,
			ExcludeANetworks: []string{"2001:db8::/32"},
		}}, "exclude_a_networks"},
		{"exclude_aaaa takes IPv6", Config{DNS64: DNS64Config{
			Enabled:             true,
			ExcludeAAAANetworks: []string{"192.0.2.0/24"},
		}}, "exclude_aaaa_networks"},
		// The updater fetches with an http.Client, so anything else never loads.
		{"blocklist scheme", Config{BlockLists: []string{"ftp://example.com/list"}}, "http"},
		{"negative tcp pool", Config{TCPKeepalive: true, TCPMaxConnections: -1}, "tcpmaxconnections"},
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
	both := &Config{DNS64: DNS64Config{Enabled: true, ClientNetworks: []string{"192.0.2.0/24", "2001:db8::/32"}}}
	if err := both.Validate(); err != nil {
		t.Fatalf("Validate() rejected a mixed-family client_networks list: %v", err)
	}
}

func TestValidateNegativeECSCacheLimit(t *testing.T) {
	cfg := &Config{}
	cfg.ECS.Enabled = true
	cfg.ECS.CacheLimitTTL.Duration = -time.Second
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "cache_limit_ttl") {
		t.Fatalf("Validate() = %v, want the negative ECS cache limit rejected", err)
	}
}

// TestValidateRootKeyAlgorithm pins that an anchor the verifier cannot use is
// caught here. Nothing downstream rejects it: NewResolver only fails on a
// record that will not parse, so an anchor like this loads and then silently
// fails every signature it is asked to verify.
//
// The accepted cases carry real key material. Truncated material is what an
// earlier version of this test used, and it passed — the check was only
// reading the algorithm, so a key of the right algorithm and the wrong shape
// went through.
func TestValidateRootKeyAlgorithm(t *testing.T) {
	// The live root KSK (key id 20326) and a generated P-256 key.
	const (
		rsaSHA256 = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
		ecdsaP256 = "FS/jjwld5fQ2hD31w4Odohy65Je3eGSYDvJgKO0qBBEFRC5fa6GvcWdLyn0sj49unyBRv3nAHAH0UtAyYLZi7w=="
		truncated = "AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3"
	)

	for _, tc := range []struct {
		name     string
		alg      string
		material string
		want     string // substring of the expected problem, "" to accept
	}{
		{"DSA is gone from the library", "3", truncated, "cannot be verified with"},
		{"ECC-GOST is gone too", "12", truncated, "cannot be verified with"},
		{"unassigned codepoint", "200", truncated, "cannot be verified with"},
		// Asked of the library, not assumed: ED448 has a name and a number
		// and still cannot be verified with.
		{"ED448 has a name but no verifier", "16", truncated, "cannot be verified with"},
		// A supported algorithm carrying material of the wrong shape. P-256
		// wants 64 bytes; this is 42. The resolver loads it and then fails
		// every signature, so it is no more usable than a dead algorithm.
		{"P-256 with material of the wrong size", "13", truncated, "public key is not usable"},
		{"RSASHA256 with a short modulus", "8", truncated, "public key is not usable"},
		{"RSASHA256 is what the root uses", "8", rsaSHA256, ""},
		{"ECDSAP256SHA256 is the successor", "13", ecdsaP256, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{DNSSEC: "on", RootKeys: []string{
				". 172800 IN DNSKEY 257 3 " + tc.alg + " " + tc.material,
			}}
			err := cfg.Validate()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate() rejected a usable anchor: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate() accepted an anchor nothing can verify with")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want a problem naming %q", err, tc.want)
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
		"version = %q\ndirectory = %q\nrootservers = [\"192.5.5.241:53\"]\nnullroute = \"not-an-ip\"\nmaxdepth_old = 30\n",
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

// TestValidateRequiresAnchorsWhenValidating pins the case that has no symptom
// until a query arrives. AutoTA needs a seed and refuses to take one from disk
// when the live set is empty, so this does not heal: every validated answer
// fails closed from the first query onward.
func TestValidateRequiresAnchorsWhenValidating(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool // whether Validate should accept
	}{
		{"validating with nothing to anchor to", Config{DNSSEC: "on"}, false},
		// A global forwarder skips the resolver entirely (handler.go returns
		// before it materializes), so it needs no anchor of its own.
		{"forwarder needs no anchor", Config{
			DNSSEC:           "on",
			ForwarderServers: []string{"1.1.1.1:53"},
		}, true},
		// A forward zone only hands over its own subtree; everything else
		// still recurses here and still needs an anchor.
		{"forward zone still recurses elsewhere", Config{
			DNSSEC:       "on",
			ForwardZones: []ForwardZoneConfig{{Name: "corp.example.", Servers: []string{"1.1.1.1:53"}}},
		}, false},
		{"dnssec off needs no anchor", Config{DNSSEC: "off"}, true},
		// A bare Config is not what Load produces: Load fills the omitted
		// value in as "on" before the gate, which TestLoadTreatsOmittedDNSSECAsOn
		// covers. Here the empty string is left permissive so a Config built
		// in code is still usable without a trust anchor.
		{"dnssec omitted on a hand-built config", Config{}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
			if !tc.want && !strings.Contains(err.Error(), "no usable root trust anchor") {
				t.Fatalf("Validate() = %v, want the missing anchor named", err)
			}
		})
	}
}

// TestValidatePortRange pins that a port is checked as a port. SplitHostPort
// only separates the halves, so ":65536" reached the listener and failed at
// bind time, and an upstream with such a port failed on every dial instead.
func TestValidatePortRange(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"listener port above range", Config{Bind: ":65536"}, false},
		{"listener port negative", Config{Bind: ":-1"}, false},
		{"api port above range", Config{API: "127.0.0.1:99999"}, false},
		{"upstream port above range", Config{RootServers: []string{"192.0.2.1:99999"}}, false},
		{"forwarder port above range", Config{ForwarderServers: []string{"1.1.1.1:70000"}}, false},
		// Nothing answers on port 0, and the dial fails per query rather
		// than at startup.
		{"upstream port zero", Config{RootServers: []string{"192.0.2.1:0"}}, false},
		// Asked of the net package, not of a number range: ":domain" really
		// does listen on 53, so a numeric test here would refuse a config
		// that works.
		{"listener service name", Config{Bind: ":domain"}, true},
		{"listener port zero asks for a free one", Config{Bind: ":0"}, true},
		{"ordinary listener", Config{Bind: ":53"}, true},
		{"ordinary upstream", Config{RootServers: []string{"192.0.2.1:53"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
		})
	}
}

// TestValidateMirrorsRuntimeTrimming pins which lists tolerate surrounding
// space. dns64 reads every list through TrimSpace and the hyperlocal manager
// trims and drops blanks, so rejecting those would refuse configs the server
// runs today. The ecs list is parsed raw, so it is judged raw.
func TestValidateMirrorsRuntimeTrimming(t *testing.T) {
	trimmed := &Config{
		DNS64: DNS64Config{
			Enabled:             true,
			Prefixes:            []string{" 64:ff9b::/96 "},
			ClientNetworks:      []string{" 192.0.2.0/24 "},
			ExcludeANetworks:    []string{" 10.0.0.0/8 "},
			ExcludeAAAANetworks: []string{" 2001:db8::/32 "},
			ExcludeZones:        []string{" Example.COM ", ""},
		},
		HyperlocalRoot:        true,
		HyperlocalRootSources: []string{" 192.0.2.1:53 ", ""},
		// Hyperlocal verifies every transfer against these, so it needs one.
		RootKeys: []string{". 172800 IN DNSKEY 257 3 13 " + testP256},
	}
	if err := trimmed.Validate(); err != nil {
		t.Fatalf("Validate() rejected values the runtime trims and uses: %v", err)
	}

	raw := &Config{ECS: ECSConfig{Enabled: true, ClientNetworks: []string{" 192.0.2.0/24 "}}}
	if err := raw.Validate(); err == nil {
		t.Fatal("Validate() accepted an untrimmed ecs network; ecs parses it raw and would fail")
	}
}

// TestValidateSkipsDisabledFeatures pins the upgrade path. Both constructors
// return before reading another field when the feature is off, so a stale
// value under a disabled section has no effect — and refusing to start over it
// would turn an upgrade into an outage.
func TestValidateSkipsDisabledFeatures(t *testing.T) {
	stale := &Config{
		DNS64: DNS64Config{
			Enabled:             false,
			Prefixes:            []string{"not-a-prefix", "2001:db8::/49"},
			ClientNetworks:      []string{"nonsense"},
			ExcludeANetworks:    []string{"2001:db8::/32"},
			ExcludeAAAANetworks: []string{"192.0.2.0/24"},
			ExcludeZones:        []string{"\\"},
		},
		ECS: ECSConfig{
			Enabled:        false,
			ForwardV4Max:   99,
			ClientNetworks: []string{"nonsense"},
		},
		HyperlocalRoot:        false,
		HyperlocalRootSources: []string{"no-port-at-all"},
	}
	if err := stale.Validate(); err != nil {
		t.Fatalf("Validate() refused a config whose broken values are all under disabled features: %v", err)
	}

	// Turning the feature on is what makes them count.
	on := *stale
	on.DNS64.Enabled = true
	on.ECS.Enabled = true
	on.HyperlocalRoot = true
	err := on.Validate()
	if err == nil {
		t.Fatal("Validate() accepted broken values under enabled features")
	}
	for _, want := range []string{"dns64 prefix", "ecs forward_v4", "hyperlocal_root_sources"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v\nmissing a problem for %q", err, want)
		}
	}
}

func TestValidatePathKinds(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A directory satisfies Stat and then fails at the read, taking the TLS
	// listener down after this test reported success.
	tlsCfg := &Config{
		BindTLS:        ":853",
		TLSCertificate: dir,
		TLSPrivateKey:  dir,
	}
	err := tlsCfg.Validate()
	if err == nil || !strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("Validate() = %v, want the certificate directory rejected", err)
	}

	if err := (&Config{HostsFile: dir}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "is a directory") {
		t.Fatalf("Validate() = %v, want a directory rejected as hostsfile", err)
	}

	// Absent is fine — the server creates it — but a file at the path is not,
	// because the Mkdir that follows fails on it.
	if err := (&Config{Directory: filepath.Join(dir, "not-there")}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a directory the server would create: %v", err)
	}
	if err := (&Config{Directory: file}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "want a directory") {
		t.Fatalf("Validate() = %v, want a file rejected as directory", err)
	}

	// Opened with O_CREATE, so absence is fine and a directory is not.
	if err := (&Config{AccessLog: filepath.Join(dir, "new.log")}).Validate(); err != nil {
		t.Fatalf("Validate() rejected an access log the server would create: %v", err)
	}
	if err := (&Config{AccessLog: dir}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want a directory rejected as accesslog", err)
	}

	// Only read when the integration is on.
	off := &Config{}
	off.Kubernetes.Kubeconfig = filepath.Join(dir, "missing.yaml")
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate() read kubeconfig with kubernetes disabled: %v", err)
	}
	on := *off
	on.Kubernetes.Enabled = true
	if err := on.Validate(); err == nil || !strings.Contains(err.Error(), "kubeconfig") {
		t.Fatalf("Validate() = %v, want the missing kubeconfig reported", err)
	}
}

func TestValidateNullrouteFamilies(t *testing.T) {
	// Blocked names answer A from nullroute and AAAA from nullroutev6, so a
	// swap produces a wrong answer rather than a failure.
	if err := (&Config{Nullroute: "::1"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "must be IPv4") {
		t.Fatalf("Validate() = %v, want an IPv6 nullroute rejected", err)
	}
	if err := (&Config{Nullroutev6: "0.0.0.0"}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "must be IPv6") {
		t.Fatalf("Validate() = %v, want an IPv4 nullroutev6 rejected", err)
	}
	// What the generated config ships.
	if err := (&Config{Nullroute: "0.0.0.0", Nullroutev6: "::0"}).Validate(); err != nil {
		t.Fatalf("Validate() rejected the shipped null routes: %v", err)
	}
}

func TestValidateSilentlyAdjustedNumbers(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool // accept?
	}{
		// The cache raises anything under 1024, so the file described a
		// server that never ran.
		{"cachesize below the floor", Config{CacheSize: 1}, false},
		{"cachesize zero means default", Config{CacheSize: 0}, true},
		{"cachesize at the floor", Config{CacheSize: 1024}, true},
		// 1-9 is raised to 10, and above 90 turns prefetch off entirely.
		{"prefetch below the floor", Config{Prefetch: 1}, false},
		{"prefetch zero is off", Config{Prefetch: 0}, true},
		{"prefetch at the floor", Config{Prefetch: 10}, true},
		{"prefetch at the ceiling", Config{Prefetch: 90}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
		})
	}
}

// TestLoadValidatesQnameBeforeNormalizing pins the ordering. Normalizing folds
// a negative count to zero — which turns minimization off — so running it
// first handed Validate the settled value and hid what the file said.
func TestLoadValidatesQnameBeforeNormalizing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf(
		"version = %q\ndirectory = %q\ndnssec = \"off\"\nrootservers = [\"192.5.5.241:53\"]\nqname_max_minimize_count = -1\n",
		configver, filepath.Join(dir, "db"),
	)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "test"); err == nil ||
		!strings.Contains(err.Error(), "qname_max_minimize_count") {
		t.Fatalf("Load() = %v, want the negative minimization count reported", err)
	}
}

func TestValidateForwardZoneReportsNameAndServers(t *testing.T) {
	err := (&Config{ForwardZones: []ForwardZoneConfig{{Name: ""}}}).Validate()
	if err == nil {
		t.Fatal("Validate() accepted a forward zone with no name and no servers")
	}
	for _, want := range []string{"has no name", "has no servers"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v\nmissing %q — one entry, one run", err, want)
		}
	}
}

func TestValidateURLsNeedAHostname(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
	}{
		// Host is ":443" and Hostname is empty; the forwarder bootstraps
		// Hostname and drops this at startup.
		{"DoH without a hostname", Config{ForwarderServers: []string{"https://:443/dns-query"}}},
		{"DoH port out of range", Config{ForwarderServers: []string{"https://example.com:99999/dns-query"}}},
		{"blocklist without a hostname", Config{BlockLists: []string{"http://:80/list"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); err == nil {
				t.Fatalf("Validate() accepted %+v", tc.cfg)
			}
		})
	}

	ok := &Config{
		ForwarderServers: []string{"https://cloudflare-dns.com/dns-query", "https://1.1.1.1:443/dns-query"},
		BlockLists:       []string{"https://example.com/list"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate() rejected usable URLs: %v", err)
	}
}

// TestLoadTreatsOmittedDNSSECAsOn pins the effective value, not the written
// one. Load fills an omitted dnssec in as "on", so a file naming neither it
// nor a trust anchor runs with validation on and nothing to anchor to — every
// validated answer then fails closed. The defaulting used to run after the
// gate, which is how the anchor check saw "off" and let the file through.
func TestLoadTreatsOmittedDNSSECAsOn(t *testing.T) {
	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "sdns.conf")
		content := fmt.Sprintf("version = %q\ndirectory = %q\nrootservers = [\"192.5.5.241:53\"]\n%s",
			configver, filepath.Join(dir, "db"), body)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	if _, err := Load(write(t, ""), "test"); err == nil ||
		!strings.Contains(err.Error(), "no usable root trust anchor") {
		t.Fatalf("Load() = %v, want a file with neither dnssec nor rootkeys refused", err)
	}

	// Written off is honoured, and so is a file that carries an anchor.
	if _, err := Load(write(t, "dnssec = \"off\"\n"), "test"); err != nil {
		t.Fatalf("Load() refused a file that turns validation off: %v", err)
	}
}

// TestValidateRootKeyOnCurve pins the gap the signature probe cannot see. A
// throwaway signature decodes to r = s = 0 and ecdsa.Verify rejects that
// before looking at the public point, so a curve key of the right length that
// is not on the curve came back as a bad signature and looked usable.
func TestValidateRootKeyOnCurve(t *testing.T) {
	zeros := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }

	for _, tc := range []struct {
		name string
		alg  string
		key  string
	}{
		{"P-256 right length, not on the curve", "13", zeros(64)},
		{"P-384 right length, not on the curve", "14", zeros(96)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{DNSSEC: "on", RootKeys: []string{". 172800 IN DNSKEY 257 3 " + tc.alg + " " + tc.key}}
			err := cfg.Validate()
			if err == nil || !strings.Contains(err.Error(), "not usable") {
				t.Fatalf("Validate() = %v, want the off-curve key rejected", err)
			}
		})
	}

	// A real key of the same algorithm must still pass.
	const realP256 = "FS/jjwld5fQ2hD31w4Odohy65Je3eGSYDvJgKO0qBBEFRC5fa6GvcWdLyn0sj49unyBRv3nAHAH0UtAyYLZi7w=="
	ok := &Config{DNSSEC: "on", RootKeys: []string{". 172800 IN DNSKEY 257 3 13 " + realP256}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate() rejected a real P-256 anchor: %v", err)
	}
}

func TestValidateReflexGateAndNaN(t *testing.T) {
	// reflex.New returns before reading the threshold when the feature is
	// off, so a stale value there must not stop the server.
	if err := (&Config{ReflexThreshold: 42}).Validate(); err != nil {
		t.Fatalf("Validate() read the reflex threshold with the feature off: %v", err)
	}
	// Every comparison against NaN is false, including the middleware's own,
	// so it lands on the silent default exactly like an out-of-range value.
	nan := &Config{ReflexEnabled: true, ReflexThreshold: math.NaN()}
	if err := nan.Validate(); err == nil || !strings.Contains(err.Error(), "not a number") {
		t.Fatalf("Validate() = %v, want NaN rejected", err)
	}
	if err := (&Config{ReflexEnabled: true, ReflexThreshold: 0.7}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a usable threshold: %v", err)
	}
}

func TestValidatePortZeroSpellings(t *testing.T) {
	// LookupPort resolves "00" and "+0" to zero, so a comparison against the
	// literal string "0" let them through.
	for _, spelling := range []string{"0", "00", "+0"} {
		cfg := &Config{RootServers: []string{"192.0.2.1:" + spelling}}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted upstream port %q", spelling)
		}
	}
	// The same spellings are fine on a listener, where zero asks the kernel
	// for a free port.
	for _, spelling := range []string{"0", "00"} {
		if err := (&Config{Bind: ":" + spelling}).Validate(); err != nil {
			t.Fatalf("Validate() rejected listener port %q: %v", spelling, err)
		}
	}
}

func TestValidateDNS64ExcludeANeedsWellKnownPrefix(t *testing.T) {
	// exclude_a_networks is only consulted under the well-known prefix
	// (RFC 6147 section 5.1.4); with a custom prefix the runtime never parses
	// it, so a stale entry there must not stop the server.
	custom := &Config{DNS64: DNS64Config{
		Enabled:          true,
		Prefixes:         []string{"2001:db8::/32"},
		ExcludeANetworks: []string{"nonsense"},
	}}
	if err := custom.Validate(); err != nil {
		t.Fatalf("Validate() read exclude_a_networks under a custom prefix: %v", err)
	}

	// With the well-known prefix in the set it is read, so it is judged.
	wellKnown := &Config{DNS64: DNS64Config{
		Enabled:          true,
		Prefixes:         []string{"2001:db8::/32", "64:ff9b::/96"},
		ExcludeANetworks: []string{"nonsense"},
	}}
	if err := wellKnown.Validate(); err == nil ||
		!strings.Contains(err.Error(), "exclude_a_networks") {
		t.Fatalf("Validate() = %v, want the exclude list judged under the well-known prefix", err)
	}

	// No prefixes at all means the runtime falls back to the well-known one.
	fallback := &Config{DNS64: DNS64Config{
		Enabled:          true,
		ExcludeANetworks: []string{"nonsense"},
	}}
	if err := fallback.Validate(); err == nil {
		t.Fatal("Validate() skipped exclude_a_networks when the default prefix applies")
	}
}

func TestValidateCreatedPathsNeedTheirParent(t *testing.T) {
	dir := t.TempDir()

	// Created with Mkdir, not MkdirAll: one missing level is made, two are not.
	if err := (&Config{Directory: filepath.Join(dir, "one")}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a directory Mkdir would create: %v", err)
	}
	if err := (&Config{Directory: filepath.Join(dir, "one", "two")}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "parent") {
		t.Fatalf("Validate() = %v, want the missing parent reported", err)
	}

	// The access log is created on open, but only inside an existing directory.
	if err := (&Config{AccessLog: filepath.Join(dir, "gone", "a.log")}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want the missing access log directory reported", err)
	}
}

func TestValidateBlocklistPort(t *testing.T) {
	for _, u := range []string{"http://example.com:99999/list", "http://example.com:0/list"} {
		if err := (&Config{BlockLists: []string{u}}).Validate(); err == nil {
			t.Fatalf("Validate() accepted %q", u)
		}
	}
	if err := (&Config{BlockLists: []string{"http://example.com:8080/list"}}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a usable blocklist URL: %v", err)
	}
}

// TestValidateRootKeyPolicyErrors pins that a key the crypto packages refuse
// for their own reasons is not mistaken for a signature mismatch. Go rejects
// an RSA key under 1024 bits with a key-size policy error that is neither a
// parse failure nor a verification failure, and an anchor like that fails
// every real verification the same way.
func TestValidateRootKeyPolicyErrors(t *testing.T) {
	// RFC 3110 key material: exponent length, exponent, modulus.
	rsaKey := func(modulusBytes int) string {
		buf := []byte{3, 1, 0, 1}
		mod := make([]byte, modulusBytes)
		for i := range mod {
			mod[i] = 0xff
		}
		mod[modulusBytes-1] = 0x8d
		return base64.StdEncoding.EncodeToString(append(buf, mod...))
	}

	small := &Config{DNSSEC: "on", RootKeys: []string{". 172800 IN DNSKEY 257 3 8 " + rsaKey(64)}}
	err := small.Validate()
	if err == nil || !strings.Contains(err.Error(), "not usable") {
		t.Fatalf("Validate() = %v, want the 512-bit RSA anchor rejected", err)
	}

	// A key of a size the crypto package will work with still passes.
	big := &Config{DNSSEC: "on", RootKeys: []string{". 172800 IN DNSKEY 257 3 8 " + rsaKey(256)}}
	if err := big.Validate(); err != nil {
		t.Fatalf("Validate() rejected a 2048-bit RSA anchor: %v", err)
	}
}

func TestValidateOutboundAddressesMustBeLocal(t *testing.T) {
	// The resolver stops the process when it cannot bind to one of these.
	notMine := &Config{OutboundIPs: []string{"192.0.2.1"}}
	if err := notMine.Validate(); err == nil ||
		!strings.Contains(err.Error(), "not an address of this machine") {
		t.Fatalf("Validate() = %v, want a non-local outbound address rejected", err)
	}

	// Loopback is always here, and is what the check should accept.
	mine := &Config{OutboundIPs: []string{"127.0.0.1"}}
	if err := mine.Validate(); err != nil {
		t.Fatalf("Validate() rejected a local address: %v", err)
	}

	// The v6 list is only read when ipv6access is on.
	off := &Config{OutboundIP6s: []string{"2001:db8::1"}}
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate() read outboundip6s with ipv6access off: %v", err)
	}
	on := &Config{IPv6Access: true, OutboundIP6s: []string{"2001:db8::1"}}
	if err := on.Validate(); err == nil {
		t.Fatal("Validate() accepted a non-local outbound v6 address with ipv6access on")
	}
}

// TestValidateShadowedQnameSetting pins that the deprecated key is judged only
// when it is the one being read. With the new key set, QnameMinimizeParams
// never consults it, so refusing a stale value there would stop a server whose
// live setting is fine.
func TestValidateShadowedQnameSetting(t *testing.T) {
	zero := 0
	shadowed := &Config{QnameMinLevel: -1, QnameMaxMinimizeCount: &zero}
	if err := shadowed.Validate(); err != nil {
		t.Fatalf("Validate() judged a shadowed deprecated setting: %v", err)
	}

	alone := &Config{QnameMinLevel: -1}
	if err := alone.Validate(); err == nil ||
		!strings.Contains(err.Error(), "qname_min_level") {
		t.Fatalf("Validate() = %v, want the live deprecated setting judged", err)
	}
}

func TestValidateTCPPoolSettingsFollowKeepalive(t *testing.T) {
	stale := &Config{TCPMaxConnections: -1}
	stale.RootTCPTimeout.Duration = -time.Second
	if err := stale.Validate(); err != nil {
		t.Fatalf("Validate() read TCP pool settings with keepalive off: %v", err)
	}

	on := *stale
	on.TCPKeepalive = true
	err := on.Validate()
	if err == nil {
		t.Fatal("Validate() accepted negative TCP pool settings with keepalive on")
	}
	for _, want := range []string{"tcpmaxconnections", "roottcptimeout"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Validate() = %v\nmissing %q", err, want)
		}
	}
}

func TestValidateKubernetesDemoCountsAsEnabled(t *testing.T) {
	demo := &Config{}
	demo.Kubernetes.Demo = true
	demo.Kubernetes.ClusterDomain = "bad..domain"
	if err := demo.Validate(); err == nil ||
		!strings.Contains(err.Error(), "cluster_domain") {
		t.Fatalf("Validate() = %v, want the demo cluster domain judged", err)
	}

	off := &Config{}
	off.Kubernetes.ClusterDomain = "bad..domain"
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate() judged the cluster domain with kubernetes off: %v", err)
	}

	// Trailing dot and case are normalized before use, so both are fine.
	ok := &Config{}
	ok.Kubernetes.Enabled = true
	ok.Kubernetes.ClusterDomain = "Cluster.Local."
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate() rejected a normalizable cluster domain: %v", err)
	}
}

// TestValidateLeavesListenerHostAlone pins a deliberate absence. A literal may
// name an address this machine does not hold yet — that is how a floating
// address is served, and rejecting it would refuse a working HA config — and
// whether a name resolves is a runtime question of the same class as whether
// an upstream answers.
func TestValidateLeavesListenerHostAlone(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		{"empty host is every interface", Config{Bind: ":53"}, true},
		{"IP literal", Config{Bind: "127.0.0.1:53"}, true},
		{"IPv6 literal", Config{Bind: "[::1]:53"}, true},
		{"an address not held yet", Config{Bind: "192.0.2.1:53"}, true},
		{"a name is left to listen time", Config{Bind: "localhost:53"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
		})
	}
}

// TestLoadRequiresWhatOnlyAFileNeeds pins the requirements that cannot live in
// Validate, because a Config built in code legitimately leaves them empty.
// They still have to reach the same report.
func TestLoadRequiresWhatOnlyAFileNeeds(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		want string
	}{
		{"no working directory", "directory = \"\"\nrootservers = [\"192.5.5.241:53\"]\n", "leaves it empty"},
		{"nothing to recurse from", "rootservers = []\n", "rootservers: none configured"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "sdns.conf")
			body := fmt.Sprintf("version = %q\ndnssec = \"off\"\n%s", configver, tc.body)
			if !strings.Contains(tc.body, "directory = ") {
				body = fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\n%s",
					configver, filepath.Join(dir, "db"), tc.body)
			}
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := Load(path, "test")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load() = %v, want a problem naming %q", err, tc.want)
			}
		})
	}

	// Forwarding is not an exemption. The resolver is built either way and
	// its background goroutine primes the root as soon as the middleware is
	// ready, so an empty list stops the process before a query arrives —
	// keeping the resolver out of the query path is not keeping it out of
	// the process.
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\nforwarderservers = [\"1.1.1.1:53\"]\n",
		configver, filepath.Join(dir, "db"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, "test"); err == nil ||
		!strings.Contains(err.Error(), "rootservers") {
		t.Fatalf("Load() = %v, want a forwarder-only config still to need a root", err)
	}
}

func TestValidateAccessLogTargetKinds(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.log")
	if err := os.WriteFile(file, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{AccessLog: file}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a writable access log: %v", err)
	}

}

func TestValidateDanglingSymlinkDirectory(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "db")
	if err := os.Symlink(filepath.Join(dir, "nowhere"), link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// Stat calls this absent, but the directory entry is there, so the Mkdir
	// that follows fails with EEXIST.
	if err := (&Config{Directory: link}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Validate() = %v, want the dangling symlink reported", err)
	}

	// One that resolves to a directory is usable.
	target := filepath.Join(dir, "real")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "good")
	if err := os.Symlink(target, good); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{Directory: good}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a symlink to a directory: %v", err)
	}
}

// TestUsablePortUsesTheNetworksGiven pins that the protocols a caller passes
// actually reach LookupPort. The service tables on this platform are not
// partitioned by protocol, so no config-level test can tell "udp" from "tcp"
// here; asking for a network that cannot exist proves the argument is used.
func TestUsablePortUsesTheNetworksGiven(t *testing.T) {
	if _, err := usablePort("53", "udp", "tcp"); err != nil {
		t.Fatalf("usablePort() rejected 53 on udp and tcp: %v", err)
	}
	// A numeric port is network-independent and short-circuits, so the proof
	// has to use a service name: looking one up needs a network that exists.
	if _, err := usablePort("domain", "nonsense"); err == nil {
		t.Fatal("usablePort() ignored the network it was given")
	}
	if _, err := usablePort("domain", "udp", "tcp"); err != nil {
		t.Fatalf("usablePort() rejected a service name both protocols know: %v", err)
	}
	// No networks means nothing to check, which is not a silent pass for a
	// port that cannot resolve — every caller names at least one.
	if n, err := usablePort("65536", "udp"); err == nil {
		t.Fatalf("usablePort() = %d, want an out-of-range port refused", n)
	}
}

// TestLoadSettlesIPv6BeforeJudgingIt pins the ordering. The probe decides
// whether the v6 lists are read at all, so running it after the gate meant
// outboundip6s went unjudged on a host that then used it, and a file whose
// only roots are v6 passed on a host that then had none.
func TestLoadSettlesIPv6BeforeJudgingIt(t *testing.T) {
	original := ipv6Probe
	defer func() { ipv6Probe = original }()

	write := func(t *testing.T, body string) string {
		t.Helper()
		dir := t.TempDir()
		path := filepath.Join(dir, "sdns.conf")
		content := fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\n%s",
			configver, filepath.Join(dir, "db"), body)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}

	// With v6 reachable the v6-only outbound address is read, and a
	// non-local one stops the resolver.
	ipv6Probe = func() error { return nil }
	if _, err := Load(write(t, "rootservers = [\"192.5.5.241:53\"]\noutboundip6s = [\"2001:db8::1\"]\n"), "test"); err == nil {
		t.Fatal("Load() accepted a non-local outbound v6 address on a v6 host")
	}

	// Without v6 the same file is fine, because nothing reads the list.
	ipv6Probe = func() error { return errors.New("no v6") }
	if _, err := Load(write(t, "rootservers = [\"192.5.5.241:53\"]\noutboundip6s = [\"2001:db8::1\"]\n"), "test"); err != nil {
		t.Fatalf("Load() judged outboundip6s on a host without v6: %v", err)
	}

	// v6-only roots are the whole root set on a v6 host, and none of it
	// without.
	v6Only := "root6servers = [\"[2001:500:2f::f]:53\"]\n"
	ipv6Probe = func() error { return nil }
	if _, err := Load(write(t, v6Only), "test"); err != nil {
		t.Fatalf("Load() refused v6-only roots on a v6 host: %v", err)
	}
	ipv6Probe = func() error { return errors.New("no v6") }
	if _, err := Load(write(t, v6Only), "test"); err == nil ||
		!strings.Contains(err.Error(), "rootservers") {
		t.Fatalf("Load() = %v, want v6-only roots to leave nothing on a v4 host", err)
	}
}

func TestValidateAccessLogFollowsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.log")
	if err := os.WriteFile(target, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.log")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// OpenFile follows the link, so a link to a writable file is usable and
	// refusing it would stop a setup that runs today.
	if err := (&Config{AccessLog: link}).Validate(); err != nil {
		t.Fatalf("Validate() rejected an access log symlink to a writable file: %v", err)
	}
}

func TestValidateClusterDomainTrailingDots(t *testing.T) {
	for _, tc := range []struct {
		domain string
		want   bool
	}{
		{"cluster.local", true},
		{"cluster.local.", true},
		// One dot is stripped and one put back, so this becomes a suffix
		// with a doubled dot that no query can match.
		{"cluster.local..", false},
		{"bad..domain", false},
	} {
		t.Run(tc.domain, func(t *testing.T) {
			cfg := &Config{}
			cfg.Kubernetes.Enabled = true
			cfg.Kubernetes.ClusterDomain = tc.domain
			if err := cfg.Validate(); (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
		})
	}
}

func TestValidateQnameEffectivePair(t *testing.T) {
	count := func(n int) *int { return &n }

	for _, tc := range []struct {
		name string
		cfg  Config
		want bool
	}{
		// Quietly lowered to the maximum, so the file describes a server
		// that never ran.
		{"one-label above the maximum", Config{
			QnameMaxMinimizeCount: count(3), QnameMinimizeOneLabel: 10,
		}, false},
		{"one-label at the maximum", Config{
			QnameMaxMinimizeCount: count(3), QnameMinimizeOneLabel: 3,
		}, true},
		// With minimization off the field is never read, so a stale value
		// there must not stop the server.
		{"minimization off", Config{
			QnameMaxMinimizeCount: count(0), QnameMinimizeOneLabel: -1,
		}, true},
		{"negative while on", Config{
			QnameMaxMinimizeCount: count(5), QnameMinimizeOneLabel: -1,
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.cfg.Validate(); (err == nil) != tc.want {
				t.Fatalf("Validate() accepted = %v, want %v (err = %v)", err == nil, tc.want, err)
			}
		})
	}
}

func TestValidateUpstreamProtocols(t *testing.T) {
	// DoT is dialled over TCP only; plain DNS asks over UDP and retries over
	// TCP when an answer does not fit, so both tables have to know the port.
	ok := &Config{
		RootServers:      []string{"192.5.5.241:domain"},
		ForwarderServers: []string{"tls://1.1.1.1:853", "1.1.1.1:53"},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate() rejected upstreams both tables know: %v", err)
	}
	// Port 0 has nothing to reach on either.
	for _, cfg := range []Config{
		{ForwarderServers: []string{"tls://1.1.1.1:0"}},
		{ForwarderServers: []string{"1.1.1.1:0"}},
	} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate() accepted %+v", cfg.ForwarderServers)
		}
	}
}

// TestPortNetworksPerCaller pins which protocols each setting is judged over.
// This platform's service tables answer the same for udp and tcp, so no value
// can distinguish them; recording the question can.
func TestPortNetworksPerCaller(t *testing.T) {
	original := lookupPort
	defer func() { lookupPort = original }()

	var asked []string
	lookupPort = func(network, port string) (int, error) {
		asked = append(asked, network)
		return original(network, port)
	}

	for _, tc := range []struct {
		name string
		cfg  Config
		want []string
	}{
		// The plain listener answers over both; DoH brings HTTP/3 with it.
		{"bind", Config{Bind: ":53"}, []string{"udp", "tcp"}},
		{"binddoh", Config{BindDOH: ":443", TLSCertificate: "x", TLSPrivateKey: "x"}, []string{"udp", "tcp"}},
		{"binddoq", Config{BindDOQ: ":853", TLSCertificate: "x", TLSPrivateKey: "x"}, []string{"udp"}},
		{"bindtls", Config{BindTLS: ":853", TLSCertificate: "x", TLSPrivateKey: "x"}, []string{"tcp"}},
		{"api", Config{API: "127.0.0.1:8080"}, []string{"tcp"}},
		// Plain DNS retries over TCP when an answer does not fit.
		{"rootservers", Config{RootServers: []string{"192.5.5.241:53"}}, []string{"udp", "tcp"}},
		// DoT is TCP only.
		{"DoT upstream", Config{ForwarderServers: []string{"tls://1.1.1.1:853"}}, []string{"tcp"}},
		{"plain upstream", Config{ForwarderServers: []string{"1.1.1.1:53"}}, []string{"udp", "tcp"}},
		{"blocklist", Config{BlockLists: []string{"http://example.com:8080/list"}}, []string{"tcp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			asked = nil
			_ = tc.cfg.Validate()
			if strings.Join(asked, ",") != strings.Join(tc.want, ",") {
				t.Fatalf("asked %v, want %v", asked, tc.want)
			}
		})
	}
}

// TestValidateEd25519Points pins that a key the verifier cannot work with is
// refused. ed25519.Verify answers false for a bad key and a bad signature
// alike, which is why the shared probe cannot tell them apart; VerifyWithOptions
// separates them, so nothing but "the signature is wrong" is accepted here.
func TestValidateEd25519Points(t *testing.T) {
	anchor := func(raw []byte) *Config {
		return &Config{DNSSEC: "on", RootKeys: []string{
			". 172800 IN DNSKEY 257 3 15 " + base64.StdEncoding.EncodeToString(raw),
		}}
	}
	// Little-endian y, sign bit clear.
	yEncoding := func(y *big.Int) []byte {
		be := y.Bytes()
		raw := make([]byte, ed25519.PublicKeySize)
		for i, b := range be {
			raw[len(be)-1-i] = b
		}
		return raw
	}
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))

	for _, tc := range []struct {
		name string
		key  []byte
	}{
		// Below the field prime, so it decodes — and still not a point on
		// the curve. This is the case a canonical-encoding test misses.
		{"canonical y=2, not on the curve", yEncoding(big.NewInt(2))},
		// p+2: above the prime, so no decoder accepts it.
		{"non-canonical y=p+2", yEncoding(new(big.Int).Add(p, big.NewInt(2)))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := anchor(tc.key).Validate()
			if err == nil || !strings.Contains(err.Error(), "not usable") {
				t.Fatalf("Validate() = %v, want the key refused", err)
			}
		})
	}

	// Every real key must pass, so a check that were too strict shows here.
	for i := 0; i < 200; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := anchor(pub).Validate(); err != nil {
			t.Fatalf("Validate() rejected a generated Ed25519 anchor: %v", err)
		}
	}
}

func TestValidateAccessLogDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	// The link points into a directory that is not there, so the open that
	// creates the file fails — but Stat calls the link itself absent, which
	// read as an ordinary missing file.
	link := filepath.Join(dir, "a.log")
	if err := os.Symlink(filepath.Join(dir, "gone", "real.log"), link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := (&Config{AccessLog: link}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want the dangling access log symlink reported", err)
	}

	// One whose target directory exists is fine: the open creates it there.
	good := filepath.Join(dir, "good.log")
	if err := os.Symlink(filepath.Join(dir, "real.log"), good); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{AccessLog: good}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a symlink whose target can be created: %v", err)
	}
}

// TestValidateLeavesNoProbeBehind pins that the writability check undoes its
// own side effect. It creates an entry to answer a question mode bits cannot,
// and nothing it creates may outlive the call.
func TestValidateLeavesNoProbeBehind(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "db")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 5; i++ {
		if err := (&Config{Directory: target, AccessLog: filepath.Join(target, "a.log")}).Validate(); err != nil {
			t.Fatalf("Validate() failed on a writable directory: %v", err)
		}
	}

	for _, d := range []string{dir, target} {
		entries, err := os.ReadDir(d)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if strings.HasPrefix(e.Name(), ".sdns-config-test-") {
				t.Fatalf("probe file left behind in %s: %s", d, e.Name())
			}
		}
	}
}

func TestValidateRoot6ServersFollowIPv6Access(t *testing.T) {
	// The resolver reads this list only behind ipv6access, so a stale entry
	// on a host without v6 has no effect and must not stop the server.
	stale := &Config{RootServers: []string{"192.5.5.241:53"}, Root6Servers: []string{"nonsense"}}
	if err := stale.Validate(); err != nil {
		t.Fatalf("Validate() read root6servers with ipv6access off: %v", err)
	}

	on := *stale
	on.IPv6Access = true
	if err := on.Validate(); err == nil || !strings.Contains(err.Error(), "root6servers") {
		t.Fatalf("Validate() = %v, want root6servers judged when v6 is in use", err)
	}
}

// TestValidateWildcardBelongsToTheBlocklist pins which list reads the star.
// set() strips "*." and files the rest as a wildcard block; the whitelist is
// stored verbatim and matched up the hierarchy, so a star there is a literal
// label no query produces — and the operator who wrote it, meaning to exempt
// the subdomains, gets nothing.
func TestValidateWildcardBelongsToTheBlocklist(t *testing.T) {
	if err := (&Config{Blocklist: []string{"*.example.com"}}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a wildcard block: %v", err)
	}

	err := (&Config{Whitelist: []string{"*.example.com"}}).Validate()
	if err == nil || !strings.Contains(err.Error(), "blocklist syntax") {
		t.Fatalf("Validate() = %v, want the wildcard whitelist entry rejected", err)
	}

	// The name itself is what works there, and it covers the subdomains.
	if err := (&Config{Whitelist: []string{"example.com"}}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a plain whitelist entry: %v", err)
	}
}

func TestValidateTrailingSlashDirectory(t *testing.T) {
	dir := t.TempDir()
	// Dir("/parent/db/") is "/parent/db" — the path itself, which read as a
	// parent that is not there. os.Mkdir takes the trailing slash fine.
	withSlash := filepath.Join(dir, "db") + string(filepath.Separator)
	if err := (&Config{Directory: withSlash}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a directory written with a trailing slash: %v", err)
	}
	// And the real case still fails: two missing levels, one Mkdir.
	if err := (&Config{Directory: filepath.Join(dir, "a", "b")}).Validate(); err == nil {
		t.Fatal("Validate() accepted a directory whose parent is missing")
	}
}

func TestValidateEmptyZonesMustBeServedLocally(t *testing.T) {
	// Outside the tree: the middleware drops it, and a list where every
	// entry is dropped falls back to all of them.
	outside := &Config{EmptyZones: []string{"example.com."}}
	if err := outside.Validate(); err == nil ||
		!strings.Contains(err.Error(), "locally-served") {
		t.Fatalf("Validate() = %v, want an unserved empty zone reported", err)
	}

	for _, zone := range []string{
		"10.in-addr.arpa.",
		"10.IN-ADDR.ARPA",      // canonicalized before the walk
		"sub.10.in-addr.arpa.", // covered by its parent, as Match walks suffixes
	} {
		if err := (&Config{EmptyZones: []string{zone}}).Validate(); err != nil {
			t.Fatalf("Validate() rejected %q: %v", zone, err)
		}
	}
}

// TestValidateAccessLogTrailingSlash pins that a file path keeps the meaning
// of its trailing separator. Cleaning it away — which a directory path wants —
// took the parent from one level too high and passed a name os.OpenFile
// refuses, leaving access logging quietly switched off.
func TestValidateAccessLogTrailingSlash(t *testing.T) {
	dir := t.TempDir()

	for _, suffix := range []string{"/", string(os.PathSeparator)} {
		path := filepath.Join(dir, "new.log") + suffix
		err := (&Config{AccessLog: path}).Validate()
		if err == nil || !strings.Contains(err.Error(), "accesslog") {
			t.Fatalf("Validate(%q) = %v, want the directory-shaped name refused", path, err)
		}
	}

	// Without the separator the same target is fine: the open creates it.
	if err := (&Config{AccessLog: filepath.Join(dir, "new.log")}).Validate(); err != nil {
		t.Fatalf("Validate() rejected an access log the server would create: %v", err)
	}
	// And a directory path still tolerates its own trailing separator.
	if err := (&Config{Directory: filepath.Join(dir, "db") + "/"}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a directory written with a trailing slash: %v", err)
	}
}

// TestValidateAccessLogSymlinkShape pins the two ways a link can name a
// directory without looking like one. Join cleans a trailing separator off a
// relative target, and a chain hides the shape of its final hop — in both
// cases os.OpenFile refuses the name and access logging silently goes off.
func TestValidateAccessLogSymlinkShape(t *testing.T) {
	for _, tc := range []struct {
		name  string
		links [][2]string // link name -> target, in creation order
		log   string
	}{
		{"relative target names a directory", [][2]string{
			{"access.log", "real.log/"},
		}, "access.log"},
		{"chain ending in a directory-shaped hop", [][2]string{
			{"mid.log", "end.log/"},
			{"a.log", "mid.log"},
		}, "a.log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, l := range tc.links {
				if err := os.Symlink(l[1], filepath.Join(dir, l[0])); err != nil {
					t.Skipf("symlink: %v", err)
				}
			}
			path := filepath.Join(dir, tc.log)
			if err := (&Config{AccessLog: path}).Validate(); err == nil ||
				!strings.Contains(err.Error(), "accesslog") {
				t.Fatalf("Validate() = %v, want the directory-shaped target refused", err)
			}
		})
	}

	// A chain that ends at a name the open can create is still fine.
	dir := t.TempDir()
	if err := os.Symlink("real.log", filepath.Join(dir, "mid.log")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := os.Symlink("mid.log", filepath.Join(dir, "a.log")); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{AccessLog: filepath.Join(dir, "a.log")}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a chain whose target can be created: %v", err)
	}
}

// TestValidateAccessLogSymlinkLoop pins the bound on the chase. A link that
// points at itself would otherwise be followed forever.
func TestValidateAccessLogSymlinkLoop(t *testing.T) {
	dir := t.TempDir()
	self := filepath.Join(dir, "loop.log")
	if err := os.Symlink("loop.log", self); err != nil {
		t.Skipf("symlink: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- (&Config{AccessLog: self}).Validate() }()

	select {
	case err := <-done:
		// Whatever it decides, it has to decide. The open cannot use this
		// name either, so an error is the honest answer.
		if err == nil {
			t.Fatal("Validate() accepted a symlink pointing at itself")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Validate() did not return on a self-referencing symlink")
	}
}

// TestValidateRootKeysOnlyWhereUsed pins that a record's meaning is judged
// only where something reads it. NewResolver parses every rootkey whatever
// the settings, but nothing asks what one means unless validation or the
// hyperlocal root does — so a stale entry under dnssec = "off" has no effect
// and must not stop the server.
func TestValidateRootKeysOnlyWhereUsed(t *testing.T) {
	stale := []string{". 172800 IN A 192.0.2.1"} // parses, and is not a DNSKEY

	off := &Config{DNSSEC: "off", RootKeys: stale}
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate() judged a rootkey nothing reads: %v", err)
	}

	// A record that will not parse is fatal at construction either way.
	broken := &Config{DNSSEC: "off", RootKeys: []string{"this is not a record"}}
	if err := broken.Validate(); err == nil {
		t.Fatal("Validate() accepted a rootkey that will not parse")
	}

	// Both readers bring the meaning back into play.
	for _, cfg := range []*Config{
		{DNSSEC: "on", RootKeys: stale},
		{DNSSEC: "off", HyperlocalRoot: true, RootKeys: stale},
	} {
		if err := cfg.Validate(); err == nil ||
			!strings.Contains(err.Error(), "must be a DNSKEY") {
			t.Fatalf("Validate() = %v, want the record judged when it is read", err)
		}
	}
}

// TestValidateRootForwardZoneNeedsNoAnchor pins the exemption. A forward zone
// at the root covers every name — ForwardZoneFor matches on IsSubDomain, and
// the handler hands the query on by the same early return a global forwarder
// takes — so nothing validates locally and no anchor is needed.
func TestValidateRootForwardZoneNeedsNoAnchor(t *testing.T) {
	root := &Config{
		DNSSEC:       "on",
		ForwardZones: []ForwardZoneConfig{{Name: ".", Servers: []string{"1.1.1.1:53"}}},
	}
	if err := root.Validate(); err != nil {
		t.Fatalf("Validate() asked a root forward zone for an anchor: %v", err)
	}

	// A zone below the root leaves the rest to recursion, which does need one.
	partial := &Config{
		DNSSEC:       "on",
		ForwardZones: []ForwardZoneConfig{{Name: "corp.example.", Servers: []string{"1.1.1.1:53"}}},
	}
	if err := partial.Validate(); err == nil ||
		!strings.Contains(err.Error(), "no usable root trust anchor") {
		t.Fatalf("Validate() = %v, want a subtree zone still to need an anchor", err)
	}

	// And a zone with no servers is skipped by ForwardZoneFor, so it forwards
	// nothing and cannot stand in for one.
	empty := &Config{
		DNSSEC:       "on",
		ForwardZones: []ForwardZoneConfig{{Name: ".", Servers: nil}},
	}
	if err := empty.Validate(); err == nil ||
		!strings.Contains(err.Error(), "no usable root trust anchor") {
		t.Fatalf("Validate() = %v, want a serverless root zone not to exempt", err)
	}
}

func TestValidateOutboundIPv6ListSkippedWhole(t *testing.T) {
	// The runtime does not read this list at all without v6, so nothing in
	// it — not even a value that is not an address — can matter.
	stale := &Config{OutboundIP6s: []string{"stale-value", "192.0.2.1"}}
	if err := stale.Validate(); err != nil {
		t.Fatalf("Validate() read outboundip6s with ipv6access off: %v", err)
	}

	on := *stale
	on.IPv6Access = true
	if err := on.Validate(); err == nil ||
		!strings.Contains(err.Error(), "outboundip6s") {
		t.Fatalf("Validate() = %v, want the list judged when v6 is in use", err)
	}
}

func TestValidateDefaultBlocklistDir(t *testing.T) {
	dir := t.TempDir()

	// A fresh install: neither the working directory nor the default
	// blocklist directory exists yet, and Load creates both in turn.
	fresh := &Config{Directory: filepath.Join(dir, "db")}
	if err := fresh.Validate(); err != nil {
		t.Fatalf("Validate() refused a fresh working directory: %v", err)
	}

	// A plain file sitting where the default would go stops the middleware
	// from creating it, and both list sources go quietly unloaded.
	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "blacklists"), []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{Directory: work}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "blocklistdir") {
		t.Fatalf("Validate() = %v, want the occupied default reported", err)
	}
}

// TestValidateAcceptsPathsWhoseComponentsExist is the half that holds
// everywhere. The ".." cases differ by platform and live in the unix file,
// because Windows collapses ".." before it touches the filesystem.
func TestValidateAcceptsPathsWhoseComponentsExist(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "there"), 0o750); err != nil {
		t.Fatal(err)
	}
	sep := string(filepath.Separator)
	// Built by hand: filepath.Join cleans too, so the components would not
	// survive to be judged.
	okPath := dir + sep + "there" + sep + ".." + sep + "db"
	if err := (&Config{Directory: okPath}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a path whose components all exist: %v", err)
	}
}

// TestValidateHyperlocalNeedsAnAnchor pins that hyperlocal is not covered by
// the DNSSEC rule. The manager verifies every transfer against these keys and
// gives up on each refresh while there are none, so with an empty set the
// feature never loads the zone at all — whatever dnssec says.
func TestValidateHyperlocalNeedsAnAnchor(t *testing.T) {
	bare := &Config{DNSSEC: "off", HyperlocalRoot: true}
	if err := bare.Validate(); err == nil ||
		!strings.Contains(err.Error(), "hyperlocal_root") {
		t.Fatalf("Validate() = %v, want hyperlocal without an anchor reported", err)
	}

	// Forwarding does not excuse it: the manager runs whatever the query
	// path does.
	forwarded := *bare
	forwarded.ForwarderServers = []string{"1.1.1.1:53"}
	if err := forwarded.Validate(); err == nil {
		t.Fatal("Validate() excused hyperlocal because a forwarder is configured")
	}

	withAnchor := *bare
	withAnchor.RootKeys = []string{". 172800 IN DNSKEY 257 3 13 " + testP256}
	if err := withAnchor.Validate(); err != nil {
		t.Fatalf("Validate() rejected hyperlocal with a usable anchor: %v", err)
	}

	// And with hyperlocal off the same empty set is fine.
	off := &Config{DNSSEC: "off"}
	if err := off.Validate(); err != nil {
		t.Fatalf("Validate() asked for an anchor nothing reads: %v", err)
	}
}

func TestValidateAccessLogLongChain(t *testing.T) {
	dir := t.TempDir()

	// Twenty hops is well inside what a system follows, so Stat resolves the
	// whole chain and reports the final target as absent — which means the
	// chase here has to walk all twenty to find where the file would go. A
	// shorter bound would stop partway and hand back a path that is itself
	// another link, whose parent is this directory and exists.
	prev := "gone/real.log"
	for i := range 20 {
		name := fmt.Sprintf("h%d.log", i)
		if err := os.Symlink(prev, filepath.Join(dir, name)); err != nil {
			t.Skipf("symlink: %v", err)
		}
		prev = name
	}
	if err := (&Config{AccessLog: filepath.Join(dir, prev)}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want the missing directory at the end of the chain reported", err)
	}

	// A chain longer than any system follows is refused by the stat itself.
	deep := t.TempDir()
	prev = "end.log"
	for i := range 80 {
		name := fmt.Sprintf("h%d.log", i)
		if err := os.Symlink(prev, filepath.Join(deep, name)); err != nil {
			t.Skipf("symlink: %v", err)
		}
		prev = name
	}
	if err := (&Config{AccessLog: filepath.Join(deep, prev)}).Validate(); err == nil {
		t.Fatal("Validate() accepted a chain no system will follow")
	}
}

// TestPathHandlingOnBothPlatforms exercises the join branch this platform does
// not take. It covers the part that is pure string handling — whether a
// directory-shaped target stays directory-shaped — because that is the half a
// flag can decide.
//
// What a missing component means cannot be simulated: the answer comes from
// Stat, which collapses ".." on Windows however this package joins the path.
// That half lives in the unix file, where it is the platform's own rule.
func TestPathHandlingOnBothPlatforms(t *testing.T) {
	original := cleansPathComponents
	defer func() { cleansPathComponents = original }()

	dir := t.TempDir()
	sep := string(filepath.Separator)

	// A relative symlink target that names a directory has to stay
	// directory-shaped through the join, whichever way the join works.
	link := filepath.Join(dir, "access.log")
	if err := os.Symlink("real.log"+sep, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	for _, cleans := range []bool{false, true} {
		cleansPathComponents = cleans
		if err := (&Config{AccessLog: link}).Validate(); err == nil ||
			!strings.Contains(err.Error(), "names a directory") {
			t.Fatalf("cleansPathComponents=%v: Validate() = %v, want the shape kept", cleans, err)
		}
	}

}

// TestLoadAcceptsPathsUnderThePendingDirectory pins the first-run case. Load
// creates the working directory just after this gate, so a path whose parent
// is that directory is one the server will be able to make — refusing it made
// a fresh install impossible to start.
func TestLoadAcceptsPathsUnderThePendingDirectory(t *testing.T) {
	dir := t.TempDir()
	work := filepath.Join(dir, "sdns") // does not exist yet

	for _, tc := range []struct {
		name string
		body string
	}{
		{"access log", fmt.Sprintf("accesslog = %q\n", filepath.Join(work, "access.log"))},
		{"explicit blocklistdir", fmt.Sprintf("blocklistdir = %q\n", filepath.Join(work, "lists"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			w := filepath.Join(d, "sdns")
			body := strings.ReplaceAll(tc.body, work, w)
			path := filepath.Join(d, "sdns.conf")
			content := fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\n"+
				"rootservers = [\"192.5.5.241:53\"]\n%s", configver, w, body)
			if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path, "test"); err != nil {
				t.Fatalf("Load() refused a path under the directory it creates: %v", err)
			}
		})
	}

	// One level only: Load uses Mkdir, so a directory below that is nobody's
	// to create.
	deep := &Config{Directory: work, AccessLog: filepath.Join(work, "sub", "access.log")}
	if err := deep.Validate(); err == nil {
		t.Fatal("Validate() accepted a path two levels below a directory that is not there")
	}
}

func TestValidateBlocklistDirNeedNotBeWritable(t *testing.T) {
	dir := t.TempDir()
	lists := filepath.Join(dir, "lists")
	if err := os.Mkdir(lists, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{BlockListDir: lists}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a usable blocklist directory: %v", err)
	}

	// It still has to be a directory.
	file := filepath.Join(dir, "afile")
	if err := os.WriteFile(file, []byte(""), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{BlockListDir: file}).Validate(); err == nil {
		t.Fatal("Validate() accepted a plain file as the blocklist directory")
	}
}

// TestValidateRevokedAnchorIsAllowed pins RFC 5011 section 2.1 seeding. AutoTA
// records an admin-configured revoked key as a tombstone so the revocation
// survives a restart, and keeps it out of the active set — so it is a legal
// entry that does not count as an anchor.
func TestValidateRevokedAnchorIsAllowed(t *testing.T) {
	const revoked = ". 172800 IN DNSKEY 385 3 13 " + testP256
	const active = ". 172800 IN DNSKEY 257 3 13 " + testP256

	both := &Config{DNSSEC: "on", RootKeys: []string{revoked, active}}
	if err := both.Validate(); err != nil {
		t.Fatalf("Validate() refused a config seeding a revoked key alongside an active one: %v", err)
	}

	// On its own it leaves nothing to validate with, which the anchor rule
	// reports — the revoked key itself is not the problem.
	alone := &Config{DNSSEC: "on", RootKeys: []string{revoked}}
	err := alone.Validate()
	if err == nil || !strings.Contains(err.Error(), "no usable root trust anchor") {
		t.Fatalf("Validate() = %v, want the empty active set reported", err)
	}
	if strings.Contains(err.Error(), "key-signing key") {
		t.Fatalf("Validate() = %v, want the revoked key itself accepted", err)
	}
}

func TestValidateViewAnswerMustBeARecord(t *testing.T) {
	for _, answer := range []string{"", "   ", "; a comment", "$TTL 300"} {
		cfg := &Config{Views: []ViewConfig{{
			Zone:     "office",
			Networks: []string{"192.0.2.0/24"},
			Answers:  []string{answer},
		}}}
		if err := cfg.Validate(); err == nil ||
			!strings.Contains(err.Error(), "is not a record") {
			t.Fatalf("Validate(%q) = %v, want a line holding no record reported", answer, err)
		}
	}

	ok := &Config{Views: []ViewConfig{{
		Zone:     "office",
		Networks: []string{"192.0.2.0/24"},
		Answers:  []string{"printer.local. 300 IN A 192.0.2.10"},
	}}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("Validate() rejected a real record: %v", err)
	}
}
