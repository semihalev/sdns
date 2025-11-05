package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/semihalev/zlog/v2"
)

func TestMain(m *testing.M) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)

	code := m.Run()
	os.Exit(code)
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
			name: "non-existent config file",
			setupFunc: func() (string, func()) {
				return "/non/existent/path/config.toml", func() {}
			},
			version:     "1.4.0",
			wantErr:     true,
			errContains: "could not load config",
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
			name: "default sdns.conf with existing sdns.toml",
			setupFunc: func() (string, func()) {
				tmpDir := t.TempDir()
				oldPwd, _ := os.Getwd()
				os.Chdir(tmpDir) //nolint:gosec // G104 - test chdir

				// Create sdns.toml
				tomlConfig := fmt.Sprintf(defaultConfig, configver)
				if err := os.WriteFile("sdns.toml", []byte(tomlConfig), 0644); err != nil { //nolint:gosec // G306 - test file
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

func TestTestIPv6Network(t *testing.T) {
	// Just test that the function doesn't panic
	err := testIPv6Network()
	// We can't control the network state, so just verify it returns without panic
	_ = err
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
		"# Upstream Servers",
		"# API and Logging",
		"# Filtering and Blocking",
		"# Access Control",
		"# Performance and Limits",
		"# Rate Limiting",
		"# Custom Lists",
		"# Advanced Features",
		"# Dnstap Binary Logging",
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
		t.Error("Load() returned nil config")
	}

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
