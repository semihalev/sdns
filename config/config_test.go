package config

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

func TestMain(m *testing.M) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	// Loading a configuration probes for IPv6 connectivity, which is a real
	// query to a root server. Every test that loads one paid two seconds for
	// it on any host without IPv6 — including CI. Answer it here instead;
	// TestIPv6ProbeDecidesAccess covers the wiring.
	ipv6Probe = func() error { return errors.New("no IPv6 in tests") }

	code := m.Run()
	os.Exit(code)
}

func defaultRecursionFirewallConfigForTest(mode RecursionFirewallMode) RecursionFirewallConfig {
	return RecursionFirewallConfig{
		Mode:                    mode,
		MaxOutboundQueries:      DefaultRecursionFirewallMaxOutboundQueries,
		MaxInternalQueries:      DefaultRecursionFirewallMaxInternalQueries,
		MaxDNSKEYCandidates:     DefaultRecursionFirewallMaxDNSKEYCandidates,
		MaxRRsetSignatureChecks: DefaultRecursionFirewallMaxRRsetSignatureChecks,
		MaxSignatureChecks:      DefaultRecursionFirewallMaxSignatureChecks,
		MaxDSDigests:            DefaultRecursionFirewallMaxDSDigests,
		MaxNSEC3Hashes:          DefaultRecursionFirewallMaxNSEC3Hashes,
		MaxConcurrentCrypto:     DefaultRecursionFirewallMaxConcurrentCrypto,
		FailureCacheSize:        DefaultRecursionFirewallFailureCacheSize,
		FailureCacheMinTTL:      Duration{Duration: DefaultRecursionFirewallFailureCacheMinTTL},
		FailureCacheMaxTTL:      Duration{Duration: DefaultRecursionFirewallFailureCacheMaxTTL},
	}
}

func assertRecursionFirewallDefaults(t *testing.T, got RecursionFirewallConfig) {
	t.Helper()
	want := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
	if got != want {
		t.Errorf("RecursionFirewall = %+v, want defaults %+v", got, want)
	}
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() (string, func())
		version     string
		wantErr     bool
		errContains string
	}{
		{
			name: "load generated config",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "test.conf")
				if err := generateConfig(cfgFile); err != nil {
					t.Fatal(err)
				}
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			version: "1.4.0",
			wantErr: false,
		},
		{
			// A missing config is generated wherever the -c flag points;
			// what still fails is a path whose directory cannot be
			// written, and it fails at generation, not at load.
			name: "config path in a directory that does not exist",
			setupFunc: func() (string, func()) {
				return "/non/existent/path/config.toml", func() {}
			},
			version:     "1.4.0",
			wantErr:     true,
			errContains: "could not generate config",
		},
		{
			name: "invalid toml config",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "invalid.conf")
				if err := os.WriteFile(cfgFile, []byte("invalid = toml content ["), 0644); err != nil { //nolint:gosec // G306 - test file
					t.Fatal(err)
				}
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			version:     "1.4.0",
			wantErr:     true,
			errContains: "could not load config",
		},
		{
			name: "create working directory",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "test.conf")
				workDir := filepath.Join(tmpDir, "testdb")

				// Escape backslashes for TOML on Windows
				escapedWorkDir := strings.ReplaceAll(workDir, `\`, `\\`)
				config := strings.ReplaceAll(defaultConfig, `directory = "db"`, fmt.Sprintf(`directory = "%s"`, escapedWorkDir))
				config = fmt.Sprintf(config, configver)

				if err := os.WriteFile(cfgFile, []byte(config), 0644); err != nil { //nolint:gosec // G306 - test file //nolint:gosec // G306 - test file
					t.Fatal(err)
				}
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			version: "1.4.0",
			wantErr: false,
		},
		{
			name: "working directory permission error",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "test.conf")
				workDir := filepath.Join(tmpDir, "noperm", "testdb")

				// Create parent directory without write permission
				if err := os.Mkdir(filepath.Join(tmpDir, "noperm"), 0555); err != nil { //nolint:gosec // G301 - test file needs non-writable dir
					t.Fatal(err)
				}

				// Escape backslashes for TOML on Windows
				escapedWorkDir := strings.ReplaceAll(workDir, `\`, `\\`)
				config := strings.ReplaceAll(defaultConfig, `directory = "db"`, fmt.Sprintf(`directory = "%s"`, escapedWorkDir))
				config = fmt.Sprintf(config, configver)

				if err := os.WriteFile(cfgFile, []byte(config), 0644); err != nil { //nolint:gosec // G306 - test file //nolint:gosec // G306 - test file
					t.Fatal(err)
				}
				return cfgFile, func() {
					os.Chmod(filepath.Join(tmpDir, "noperm"), 0755) //nolint:gosec // G104 - test cleanup
					os.RemoveAll(tmpDir)                            //nolint:gosec // G104 - test cleanup
				}
			},
			version:     "1.4.0",
			wantErr:     true,
			errContains: "error creating working directory",
		},
		{
			// The sdns.toml fallback is gone with the releases that used
			// it: a leftover sdns.toml in the working directory must not
			// hijack the load — least of all for an explicit path.
			name: "leftover sdns.toml is ignored, the asked-for file is generated",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				oldPwd, _ := os.Getwd()
				os.Chdir(tmpDir) //nolint:gosec // G104 - test chdir

				if err := os.WriteFile("sdns.toml", []byte("version = \"0.0.1\"\ndirectory = \"db\"\n"), 0644); err != nil { //nolint:gosec // G306 - test file
					t.Fatal(err)
				}

				return "sdns.conf", func() {
					os.Chdir(oldPwd)     //nolint:gosec // G104 - test cleanup
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			version: "1.4.0",
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip permission test on Windows before calling setupFunc
			if strings.Contains(tt.name, "permission error") && (runtime.GOOS == "windows" || os.Getuid() == 0) {
				t.Skip("Permission test not applicable")
			}

			cfgFile, cleanup := tt.setupFunc()
			defer cleanup()

			cfg, err := Load(cfgFile, tt.version)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Load() error = nil, wantErr %v", tt.wantErr)
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Load() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("Load() unexpected error = %v", err)
				}
				if cfg == nil {
					t.Error("Load() returned nil config")
				} else {
					// Verify some defaults
					if cfg.DNSSEC != "on" {
						t.Errorf("DNSSEC = %v, want 'on'", cfg.DNSSEC)
					}
					if cfg.RFC8198 == nil || !cfg.RFC8198Enabled() {
						t.Error("generated config must explicitly enable RFC 8198")
					}
					if cfg.RecursionFirewall.Mode != RecursionFirewallModeShadow {
						t.Errorf("RecursionFirewall.Mode = %q, want %q",
							cfg.RecursionFirewall.Mode, RecursionFirewallModeShadow)
					}
					assertRecursionFirewallDefaults(t, cfg.RecursionFirewall)
					if cfg.sVersion != tt.version {
						t.Errorf("ServerVersion = %v, want %v", cfg.sVersion, tt.version)
					}
					if cfg.CookieSecret == "" {
						t.Error("CookieSecret should be generated")
					}
				}
			}
		})
	}
}

func TestDuration_UnmarshalText(t *testing.T) {
	tests := []struct {
		name    string
		text    string
		want    time.Duration
		wantErr bool
	}{
		{
			name: "valid duration",
			text: "5s",
			want: 5 * time.Second,
		},
		{
			name: "complex duration",
			text: "1h30m",
			want: 90 * time.Minute,
		},
		{
			name:    "invalid duration",
			text:    "invalid",
			wantErr: true,
		},
		{
			name:    "empty duration",
			text:    "",
			wantErr: true, // Empty string is invalid duration
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var d Duration
			err := d.UnmarshalText([]byte(tt.text))

			if tt.wantErr {
				if err == nil {
					t.Error("UnmarshalText() error = nil, wantErr true")
				}
			} else {
				if err != nil {
					t.Errorf("UnmarshalText() unexpected error = %v", err)
				}
				if d.Duration != tt.want {
					t.Errorf("Duration = %v, want %v", d.Duration, tt.want)
				}
			}
		})
	}
}

func TestServerVersion(t *testing.T) {
	cfg := &Config{sVersion: "1.2.3"}
	if v := cfg.ServerVersion(); v != "1.2.3" {
		t.Errorf("ServerVersion() = %v, want 1.2.3", v)
	}
}

func TestGenerateConfig(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() (string, func())
		wantErr     bool
		errContains string
	}{
		{
			name: "successful generation",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "new.conf")
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			wantErr: false,
		},
		{
			name: "directory does not exist error",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "subdir", "new.conf")
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			wantErr:     true,
			errContains: "could not generate config",
		},
		{
			name: "permission error",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				// Remove write permission
				os.Chmod(tmpDir, 0555) //nolint:gosec // G104 - test setup
				cfgFile := filepath.Join(tmpDir, "readonly.conf")

				return cfgFile, func() {
					os.Chmod(tmpDir, 0755) //nolint:gosec // G104 - test cleanup
					os.RemoveAll(tmpDir)   //nolint:gosec // G104 - test cleanup
				}
			},
			wantErr:     true,
			errContains: "could not generate config",
		},
		{
			name: "existing file",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				cfgFile := filepath.Join(tmpDir, "existing.conf")
				os.WriteFile(cfgFile, []byte("existing"), 0644) //nolint:gosec // G104,G306 - test setup
				return cfgFile, func() {
					os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
				}
			},
			wantErr: false, // Should overwrite
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip permission test on Windows before calling setupFunc
			if strings.Contains(tt.name, "permission error") && (runtime.GOOS == "windows" || os.Getuid() == 0) {
				t.Skip("Permission test not applicable")
			}

			cfgFile, cleanup := tt.setupFunc()
			defer cleanup()

			err := generateConfig(cfgFile)

			if tt.wantErr {
				if err == nil {
					t.Error("generateConfig() error = nil, wantErr true")
				} else if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("generateConfig() error = %v, want error containing %v", err, tt.errContains)
				}
			} else {
				if err != nil {
					t.Errorf("generateConfig() unexpected error = %v", err)
				}
				// Verify file exists and contains expected content
				if _, err := os.Stat(cfgFile); err != nil {
					t.Errorf("Config file not created: %v", err)
				}
				content, err := os.ReadFile(cfgFile) //nolint:gosec // G304 - test file read
				if err != nil {
					t.Errorf("Failed to read config file: %v", err)
				}
				if !strings.Contains(string(content), "version = ") {
					t.Error("Generated config missing version field")
				}
			}
		})
	}
}

// TestIPv6NetworkProbe covers the probe itself against a server it can
// reach, and against one that is not listening. The test this replaces
// called the real probe, waited two seconds for a root server, and then
// discarded the result — so the function was "covered" without anything
// being established about it.
func TestIPv6NetworkProbe(t *testing.T) {
	original := ipv6ProbeServer
	defer func() { ipv6ProbeServer = original }()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(r)
		_ = w.WriteMsg(reply)
	})
	server := &dns.Server{Net: "udp", PacketConn: pc, Handler: mux}
	go func() { _ = server.ActivateAndServe() }()
	defer func() { _ = server.Shutdown() }()
	time.Sleep(10 * time.Millisecond)

	ipv6ProbeServer = pc.LocalAddr().String()
	if err := testIPv6Network(); err != nil {
		t.Fatalf("a reachable server must satisfy the probe: %v", err)
	}

	// An exchange that fails has to be reported as a failure, not taken for
	// a working network. The failure comes from a server that answers with
	// something that is not a DNS message: a port assumed closed is a race
	// — the address can be taken between releasing it and using it — and
	// one that is merely silent costs the probe's whole timeout.
	broken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer broken.Close()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, readErr := broken.ReadFrom(buf)
			if readErr != nil {
				return
			}
			_, _ = broken.WriteTo([]byte("this is not a DNS message")[:min(n, 25)], from)
		}
	}()

	ipv6ProbeServer = broken.LocalAddr().String()
	if err := testIPv6Network(); err == nil {
		t.Fatal("a server that cannot answer must fail the probe")
	}
}

// TestIPv6ProbeDecidesAccess pins what the probe is for. The test it
// replaces called the real thing, waited two seconds for the network, and
// then discarded the result — it asserted nothing at all.
func TestIPv6ProbeDecidesAccess(t *testing.T) {
	original := ipv6Probe
	defer func() { ipv6Probe = original }()

	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	content := fmt.Sprintf("version = %q\ndirectory = %q\n",
		configver, filepath.Join(dir, "db"))
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	load := func() *Config {
		t.Helper()
		cfg, err := Load(path, "test")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return cfg
	}

	asked := 0
	ipv6Probe = func() error { asked++; return nil }
	if cfg := load(); !cfg.IPv6Access {
		t.Fatal("a reachable IPv6 network must turn IPv6 access on")
	}

	ipv6Probe = func() error { asked++; return errors.New("unreachable") }
	if cfg := load(); cfg.IPv6Access {
		t.Fatal("an unreachable IPv6 network must leave IPv6 access off")
	}

	if asked != 2 {
		t.Fatalf("probe ran %d times, want once per load", asked)
	}
}

func TestRecursionFirewallConfigNormalizeAndValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RecursionFirewallConfig
		want    RecursionFirewallConfig
		wantErr bool
	}{
		{
			name: "omitted uses shadow defaults",
			want: defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow),
		},
		{
			name: "explicit off keeps custom limits",
			cfg: RecursionFirewallConfig{
				Mode:                    RecursionFirewallModeOff,
				MaxOutboundQueries:      256,
				MaxInternalQueries:      48,
				MaxDNSKEYCandidates:     3,
				MaxRRsetSignatureChecks: 5,
				MaxSignatureChecks:      17,
				MaxDSDigests:            19,
				MaxNSEC3Hashes:          23,
				MaxConcurrentCrypto:     29,
				FailureCacheSize:        8192,
				FailureCacheMinTTL:      Duration{Duration: 2 * time.Second},
				FailureCacheMaxTTL:      Duration{Duration: 2 * time.Minute},
			},
			want: RecursionFirewallConfig{
				Mode:                    RecursionFirewallModeOff,
				MaxOutboundQueries:      256,
				MaxInternalQueries:      48,
				MaxDNSKEYCandidates:     3,
				MaxRRsetSignatureChecks: 5,
				MaxSignatureChecks:      17,
				MaxDSDigests:            19,
				MaxNSEC3Hashes:          23,
				MaxConcurrentCrypto:     29,
				FailureCacheSize:        8192,
				FailureCacheMinTTL:      Duration{Duration: 2 * time.Second},
				FailureCacheMaxTTL:      Duration{Duration: 2 * time.Minute},
			},
		},
		{
			name: "explicit enforce fills zero limits",
			cfg: RecursionFirewallConfig{
				Mode: RecursionFirewallModeEnforce,
			},
			want: defaultRecursionFirewallConfigForTest(RecursionFirewallModeEnforce),
		},
		{
			name: "invalid mode is rejected",
			cfg: RecursionFirewallConfig{
				Mode: "block",
			},
			want:    defaultRecursionFirewallConfigForTest("block"),
			wantErr: true,
		},
		{
			name: "failure cache minimum below RFC floor is rejected",
			cfg: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMinTTL.Duration = 999 * time.Millisecond
				return cfg
			}(),
			want: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMinTTL.Duration = 999 * time.Millisecond
				return cfg
			}(),
			wantErr: true,
		},
		{
			name: "failure cache maximum above RFC ceiling is rejected",
			cfg: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMaxTTL.Duration = 5*time.Minute + time.Second
				return cfg
			}(),
			want: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMaxTTL.Duration = 5*time.Minute + time.Second
				return cfg
			}(),
			wantErr: true,
		},
		{
			name: "failure cache maximum below minimum is rejected",
			cfg: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMinTTL.Duration = 30 * time.Second
				cfg.FailureCacheMaxTTL.Duration = 10 * time.Second
				return cfg
			}(),
			want: func() RecursionFirewallConfig {
				cfg := defaultRecursionFirewallConfigForTest(RecursionFirewallModeShadow)
				cfg.FailureCacheMinTTL.Duration = 30 * time.Second
				cfg.FailureCacheMaxTTL.Duration = 10 * time.Second
				return cfg
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.cfg
			cfg.Normalize()
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if cfg != tt.want {
				t.Errorf("normalized config = %+v, want %+v", cfg, tt.want)
			}
		})
	}
}

func TestRFC8198EnabledDefaultsAndOverrides(t *testing.T) {
	enabled := true
	disabled := false

	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{
			name: "nil config defaults on",
			want: true,
		},
		{
			name: "omitted defaults on",
			cfg:  &Config{},
			want: true,
		},
		{
			name: "explicit true",
			cfg:  &Config{RFC8198: &enabled},
			want: true,
		},
		{
			name: "explicit false",
			cfg:  &Config{RFC8198: &disabled},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.RFC8198Enabled(); got != tt.want {
				t.Fatalf("RFC8198Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadRFC8198Policy(t *testing.T) {
	tests := []struct {
		name        string
		setting     string
		wantEnabled bool
		wantSet     bool
	}{
		{
			name:        "omitted remains default on",
			wantEnabled: true,
		},
		{
			name:        "explicit true",
			setting:     "rfc8198 = true",
			wantEnabled: true,
			wantSet:     true,
		},
		{
			name:        "explicit false",
			setting:     "rfc8198 = false",
			wantEnabled: false,
			wantSet:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgFile := filepath.Join(tmpDir, "sdns.conf")
			workDir := filepath.Join(tmpDir, "db")
			content := fmt.Sprintf(`version = %q
directory = %q
ipv6access = true
%s
`, configver, workDir, tt.setting)
			if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil { //nolint:gosec // G306 - test file
				t.Fatal(err)
			}

			cfg, err := Load(cfgFile, "test")
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := cfg.RFC8198Enabled(); got != tt.wantEnabled {
				t.Fatalf("RFC8198Enabled() = %v, want %v", got, tt.wantEnabled)
			}
			if got := cfg.RFC8198 != nil; got != tt.wantSet {
				t.Fatalf("RFC8198 pointer set = %v, want %v", got, tt.wantSet)
			}
		})
	}
}

func TestRFC9520EnabledDefaultsAndOverrides(t *testing.T) {
	enabled := true
	disabled := false

	tests := []struct {
		name string
		cfg  *Config
		want bool
	}{
		{
			name: "nil config defaults on",
			want: true,
		},
		{
			name: "omitted defaults on",
			cfg:  &Config{},
			want: true,
		},
		{
			name: "explicit true",
			cfg:  &Config{RFC9520: &enabled},
			want: true,
		},
		{
			name: "explicit false",
			cfg:  &Config{RFC9520: &disabled},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.RFC9520Enabled(); got != tt.want {
				t.Fatalf("RFC9520Enabled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadRFC9520Policy(t *testing.T) {
	tests := []struct {
		name        string
		setting     string
		wantEnabled bool
		wantSet     bool
	}{
		{
			name:        "omitted remains default on",
			wantEnabled: true,
		},
		{
			name:        "explicit true",
			setting:     "rfc9520 = true",
			wantEnabled: true,
			wantSet:     true,
		},
		{
			name:        "explicit false",
			setting:     "rfc9520 = false",
			wantEnabled: false,
			wantSet:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			cfgFile := filepath.Join(tmpDir, "sdns.conf")
			workDir := filepath.Join(tmpDir, "db")
			content := fmt.Sprintf(`version = %q
directory = %q
ipv6access = true
%s
`, configver, workDir, tt.setting)
			if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil { //nolint:gosec // G306 - test file
				t.Fatal(err)
			}

			cfg, err := Load(cfgFile, "test")
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if got := cfg.RFC9520Enabled(); got != tt.wantEnabled {
				t.Fatalf("RFC9520Enabled() = %v, want %v", got, tt.wantEnabled)
			}
			if got := cfg.RFC9520 != nil; got != tt.wantSet {
				t.Fatalf("RFC9520 pointer set = %v, want %v", got, tt.wantSet)
			}
		})
	}
}

func TestLoadRecursionFirewallPolicy(t *testing.T) {
	t.Run("explicit enforce values", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "sdns.conf")
		workDir := filepath.Join(tmpDir, "db")
		content := fmt.Sprintf(`version = %q
directory = %q
ipv6access = true

[recursion_firewall]
mode = "enforce"
max_outbound_queries = 96
max_internal_queries = 24
max_dnskey_candidates = 3
max_rrset_signature_checks = 5
max_signature_checks = 17
max_ds_digests = 19
max_nsec3_hashes = 23
max_concurrent_crypto = 29
failure_cache_size = 8192
failure_cache_min_ttl = "2s"
failure_cache_max_ttl = "2m"
`, configver, workDir)
		if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil { //nolint:gosec // G306 - test file
			t.Fatal(err)
		}

		cfg, err := Load(cfgFile, "test")
		if err != nil {
			t.Fatalf("Load() error = %v", err)
		}
		if cfg.RecursionFirewall.Mode != RecursionFirewallModeEnforce {
			t.Errorf("Mode = %q, want %q",
				cfg.RecursionFirewall.Mode, RecursionFirewallModeEnforce)
		}
		if cfg.RecursionFirewall.MaxOutboundQueries != 96 {
			t.Errorf("MaxOutboundQueries = %d, want 96",
				cfg.RecursionFirewall.MaxOutboundQueries)
		}
		if cfg.RecursionFirewall.MaxInternalQueries != 24 {
			t.Errorf("MaxInternalQueries = %d, want 24",
				cfg.RecursionFirewall.MaxInternalQueries)
		}
		if cfg.RecursionFirewall.MaxDNSKEYCandidates != 3 ||
			cfg.RecursionFirewall.MaxRRsetSignatureChecks != 5 ||
			cfg.RecursionFirewall.MaxSignatureChecks != 17 ||
			cfg.RecursionFirewall.MaxDSDigests != 19 ||
			cfg.RecursionFirewall.MaxNSEC3Hashes != 23 ||
			cfg.RecursionFirewall.MaxConcurrentCrypto != 29 {
			t.Errorf("DNSSEC limits = %+v, want configured values", cfg.RecursionFirewall)
		}
		if cfg.RecursionFirewall.FailureCacheSize != 8192 ||
			cfg.RecursionFirewall.FailureCacheMinTTL.Duration != 2*time.Second ||
			cfg.RecursionFirewall.FailureCacheMaxTTL.Duration != 2*time.Minute {
			t.Errorf("Failure cache = %+v, want configured values", cfg.RecursionFirewall)
		}
	})

	t.Run("invalid mode fails before directory creation", func(t *testing.T) {
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "sdns.conf")
		workDir := filepath.Join(tmpDir, "must-not-exist")
		content := fmt.Sprintf(`version = %q
directory = %q
ipv6access = true

[recursion_firewall]
mode = "blocking"
`, configver, workDir)
		if err := os.WriteFile(cfgFile, []byte(content), 0644); err != nil { //nolint:gosec // G306 - test file
			t.Fatal(err)
		}

		_, err := Load(cfgFile, "test")
		if err == nil || !strings.Contains(err.Error(), "invalid recursion firewall config") {
			t.Fatalf("Load() error = %v, want invalid recursion firewall config", err)
		}
		if _, statErr := os.Stat(workDir); !os.IsNotExist(statErr) {
			t.Fatalf("invalid config created working directory: stat error = %v", statErr)
		}
	})
}

func TestConfigDefaults(t *testing.T) {
	// Test that default config contains all expected sections
	generatedConfig := fmt.Sprintf(defaultConfig, configver)

	expectedSections := []string{
		"# Configuration file version",
		"# Basic Server Configuration",
		"# Network Configuration",
		"# Root DNS Servers",
		"# DNSSEC Configuration",
		"rfc8198 = true",
		"rfc9520 = true",
		"# Upstream Servers",
		"# API and Logging",
		"# Filtering and Blocking",
		"# Access Control",
		"# Performance and Limits",
		"# Rate Limiting",
		"# Custom Lists",
		"# Advanced Features",
		"# Dnstap Binary Logging",
		"# Recursion Firewall",
		"# Plugins",
	}

	for _, section := range expectedSections {
		if !strings.Contains(generatedConfig, section) {
			t.Errorf("Default config missing section: %s", section)
		}
	}

	// Test dnstap configuration is included
	dnstapOptions := []string{
		"dnstapsocket",
		"dnstapidentity",
		"dnstapversion",
		"dnstaplogqueries",
		"dnstaplogresponses",
		"dnstapflushinterval",
	}

	for _, option := range dnstapOptions {
		if !strings.Contains(generatedConfig, option) {
			t.Errorf("Default config missing dnstap option: %s", option)
		}
	}

	recursionFirewallOptions := []string{
		`[recursion_firewall]`,
		`mode = "shadow"`,
		"max_outbound_queries = 128",
		"max_internal_queries = 32",
		"max_dnskey_candidates = 4",
		"max_rrset_signature_checks = 8",
		"max_signature_checks = 32",
		"max_ds_digests = 32",
		"max_nsec3_hashes = 32",
		"max_concurrent_crypto = 32",
	}
	for _, option := range recursionFirewallOptions {
		if !strings.Contains(generatedConfig, option) {
			t.Errorf("Default config missing recursion firewall option: %s", option)
		}
	}
}

func TestPackagedConfigMatchesGeneratedDefault(t *testing.T) {
	path := filepath.Join("..", "contrib", "linux", "sdns.conf")
	packaged, err := os.ReadFile(path) //nolint:gosec // G304 - fixed repository fixture
	if err != nil {
		t.Fatalf("read packaged config: %v", err)
	}
	// A Windows checkout with autocrlf gives the packaged file CRLF line
	// endings, while the Go spec discards carriage returns from raw string
	// literals — so the generated text is always LF. Normalize before
	// comparing content.
	packagedText := strings.ReplaceAll(string(packaged), "\r\n", "\n")
	generated := fmt.Sprintf(defaultConfig, configver)
	if strings.TrimSpace(packagedText) != strings.TrimSpace(generated) {
		t.Fatal("packaged config differs from the generated default")
	}
}

func TestConfigVersionMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "oldversion.conf")

	// Create config with old version
	// We need to create a minimal valid config
	minimalConfig := `version = "0.0.1"
directory = "db"
bind = ":53"
rootservers = []
root6servers = []
dnssec = "on"
rootkeys = []
fallbackservers = []
forwarderservers = []
api = "127.0.0.1:8080"
loglevel = "info"
blocklists = []
nullroute = "0.0.0.0"
nullroutev6 = "::0"
accesslist = ["0.0.0.0/0", "::0/0"]
hostsfile = ""
timeout = "2s"
querytimeout = "10s"
expire = 600
cachesize = 256000
prefetch = 10
maxdepth = 30
ratelimit = 0
clientratelimit = 0
blocklist = []
whitelist = []
nsid = ""
chaos = true
qname_min_level = 5
emptyzones = []
`

	if err := os.WriteFile(cfgFile, []byte(minimalConfig), 0644); err != nil { //nolint:gosec // G306 - test file
		t.Fatal(err)
	}

	// Load should succeed but warn about version
	cfg, err := Load(cfgFile, "1.4.0")
	if err != nil {
		t.Errorf("Load() unexpected error = %v", err)
	}
	if cfg == nil {
		t.Fatal("Load() returned nil config")
	}
	if cfg.RecursionFirewall.Mode != RecursionFirewallModeShadow {
		t.Errorf("RecursionFirewall.Mode = %q, want %q",
			cfg.RecursionFirewall.Mode, RecursionFirewallModeShadow)
	}
	assertRecursionFirewallDefaults(t, cfg.RecursionFirewall)

	// Clean up
	os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
}

func TestConfigWithDNSSECOff(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "dnssec-off.conf")

	// Create config with DNSSEC off
	config := strings.ReplaceAll(defaultConfig, `dnssec = "on"`, `dnssec = "off"`)
	config = fmt.Sprintf(config, configver)

	if err := os.WriteFile(cfgFile, []byte(config), 0644); err != nil { //nolint:gosec // G306 - test file
		t.Fatal(err)
	}

	cfg, err := Load(cfgFile, "1.4.0")
	if err != nil {
		t.Errorf("Load() unexpected error = %v", err)
	}
	if cfg.DNSSEC != "off" {
		t.Errorf("DNSSEC = %v, want 'off'", cfg.DNSSEC)
	}

	// Clean up
	os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
}

func TestConfigWithIPv6Access(t *testing.T) {
	tmpDir := t.TempDir()
	cfgFile := filepath.Join(tmpDir, "ipv6.conf")

	// Create config with IPv6 access enabled
	// Insert ipv6access before the kubernetes section
	config := strings.Replace(defaultConfig, "[kubernetes]", "ipv6access = true\n\n[kubernetes]", 1)
	config = fmt.Sprintf(config, configver)

	if err := os.WriteFile(cfgFile, []byte(config), 0644); err != nil { //nolint:gosec // G306 - test file
		t.Fatal(err)
	}

	cfg, err := Load(cfgFile, "1.4.0")
	if err != nil {
		t.Errorf("Load() unexpected error = %v", err)
	}
	if !cfg.IPv6Access {
		t.Error("IPv6Access should be true when explicitly set")
	}

	// Clean up
	os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup
}

// TestCookieSecretGenerated verifies the auto-generated DNS Cookie secret is
// full-width hex (no space padding from the old fmt.Sprintf("%16x", ...)).
func TestCookieSecretGenerated(t *testing.T) {
	cfgFile := filepath.Join(t.TempDir(), "sdns.conf")
	cfg, err := Load(cfgFile, "1.0.0")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.CookieSecret) != 32 {
		t.Fatalf("CookieSecret length = %d, want 32", len(cfg.CookieSecret))
	}
	if strings.ContainsRune(cfg.CookieSecret, ' ') {
		t.Fatalf("CookieSecret contains space padding: %q", cfg.CookieSecret)
	}
	if _, err := hex.DecodeString(cfg.CookieSecret); err != nil {
		t.Fatalf("CookieSecret is not valid hex: %v", err)
	}
}

// The -c flag promises "if it doesn't exist, a new one will be
// generated" — for whatever the file is called. The generation used to
// be gated on the default name, so every custom path was a load error
// instead of a fresh config.
func TestLoadGeneratesAConfigAtACustomPath(t *testing.T) {
	t.Chdir(t.TempDir())

	cfg, err := Load("my-resolver.conf", "test")
	if err != nil {
		t.Fatalf("load with a custom missing path: %v", err)
	}
	if cfg.Version != configver {
		t.Fatalf("generated config carries version %q, want %q", cfg.Version, configver)
	}
	if _, err := os.Stat("my-resolver.conf"); err != nil {
		t.Fatalf("the config file was not written: %v", err)
	}

	// And loading it again reads the generated file rather than
	// regenerating.
	if _, err := Load("my-resolver.conf", "test"); err != nil {
		t.Fatalf("reload: %v", err)
	}
}
