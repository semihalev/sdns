package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/BurntSushi/toml"
)

// FuzzDurationUnmarshalText fuzzes the Duration unmarshaler
// This parses user-provided duration strings like "5s", "1h30m"
func FuzzDurationUnmarshalText(f *testing.F) {
	// Add seed corpus with valid and invalid durations
	f.Add([]byte("5s"))
	f.Add([]byte("1h30m"))
	f.Add([]byte("100ms"))
	f.Add([]byte("24h"))
	f.Add([]byte("1ns"))
	f.Add([]byte("0"))
	f.Add([]byte(""))
	f.Add([]byte("invalid"))
	f.Add([]byte("-5s"))
	f.Add([]byte("9999999999999999999h"))
	f.Add([]byte("1h2m3s4ms5us6ns"))
	f.Add([]byte("1.5h"))
	f.Add([]byte(".5s"))
	f.Add([]byte("1e10s"))

	f.Fuzz(func(t *testing.T, data []byte) {
		var d Duration
		// This should not panic regardless of input
		_ = d.UnmarshalText(data)
	})
}

// FuzzConfigTOMLParsing fuzzes TOML config parsing
// This tests the robustness of config file parsing
func FuzzConfigTOMLParsing(f *testing.F) {
	// Add seed corpus with various TOML fragments
	f.Add(`version = "1.0"
directory = "db"
bind = ":53"
`)

	f.Add(`version = "1.0"
timeout = "5s"
querytimeout = "10s"
`)

	f.Add(`[kubernetes]
enabled = true
cluster_domain = "cluster.local"
`)

	f.Add(`rootservers = [
    "198.41.0.4:53",
    "199.9.14.201:53"
]`)

	f.Add(`blocklist = ["example.com", "test.com"]
whitelist = []
`)

	f.Add(`# comment
version = "1.0"
# another comment
`)

	f.Add(``)
	f.Add(`invalid toml [[[`)
	f.Add(`key = `)
	f.Add(`= value`)

	f.Fuzz(func(t *testing.T, data string) {
		var config Config
		// This should not panic regardless of input
		_, _ = toml.Decode(data, &config)
	})
}

// FuzzConfigLoad fuzzes the full config loading process
// This creates temporary config files and tests the Load function
func FuzzConfigLoad(f *testing.F) {
	// Add seed corpus with minimal valid configs
	f.Add(`version = "1.6.1"
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
accesslist = ["0.0.0.0/0"]
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
`)

	f.Add(`version = "1.6.1"
directory = "db"
dnssec = "off"
timeout = "1s"
`)

	f.Add(`version = "1.6.1"
directory = "db"
[kubernetes]
enabled = false
cluster_domain = "cluster.local"
`)

	f.Fuzz(func(t *testing.T, data string) {
		// Create a temporary directory and config file
		tmpDir := t.TempDir()
		cfgFile := filepath.Join(tmpDir, "fuzz.conf")

		if err := os.WriteFile(cfgFile, []byte(data), 0600); err != nil {
			return // Skip if we can't write the file
		}

		// This should not panic regardless of input
		_, _ = Load(cfgFile, "1.0.0-fuzz")
	})
}

// FuzzKubernetesConfig fuzzes Kubernetes-specific config parsing
func FuzzKubernetesConfig(f *testing.F) {
	f.Add(`[kubernetes]
enabled = true
cluster_domain = "cluster.local"
killer_mode = false
kubeconfig = ""

[kubernetes.ttl]
service = 30
pod = 30
srv = 30
ptr = 30
`)

	f.Add(`[kubernetes]
enabled = false
`)

	f.Add(`[kubernetes]
cluster_domain = ""
killer_mode = true
`)

	f.Fuzz(func(t *testing.T, data string) {
		var config struct {
			Kubernetes KubernetesConfig `toml:"kubernetes"`
		}
		// This should not panic regardless of input
		_, _ = toml.Decode(data, &config)
	})
}

// FuzzPluginConfig fuzzes plugin configuration parsing
func FuzzPluginConfig(f *testing.F) {
	f.Add(`[plugins]
[plugins.example]
path = "example.so"
config = {key = "value"}
`)

	f.Add(`[plugins]
[plugins.test]
path = "/path/to/plugin.so"
config = {num = 123, flag = true, str = "test"}
`)

	f.Add(`[plugins]`)
	f.Add(``)

	f.Fuzz(func(t *testing.T, data string) {
		var config struct {
			Plugins map[string]Plugin
		}
		// This should not panic regardless of input
		_, _ = toml.Decode(data, &config)
	})
}

// FuzzAccessList fuzzes access list parsing
func FuzzAccessList(f *testing.F) {
	f.Add(`accesslist = ["0.0.0.0/0", "::0/0"]`)
	f.Add(`accesslist = ["192.168.1.0/24", "10.0.0.0/8"]`)
	f.Add(`accesslist = []`)
	f.Add(`accesslist = ["invalid"]`)
	f.Add(`accesslist = ["256.256.256.256/32"]`)
	f.Add(`accesslist = ["2001:db8::/32"]`)

	f.Fuzz(func(t *testing.T, data string) {
		var config struct {
			AccessList []string
		}
		// This should not panic regardless of input
		_, _ = toml.Decode(data, &config)
	})
}

// FuzzOutboundIPs fuzzes outbound IP configuration parsing
func FuzzOutboundIPs(f *testing.F) {
	f.Add(`outboundips = ["192.168.1.1"]
outboundip6s = ["2001:db8::1"]`)

	f.Add(`outboundips = []
outboundip6s = []`)

	f.Add(`outboundips = ["0.0.0.0", "127.0.0.1", "255.255.255.255"]`)

	f.Fuzz(func(t *testing.T, data string) {
		var config struct {
			OutboundIPs  []string
			OutboundIP6s []string
		}
		// This should not panic regardless of input
		_, _ = toml.Decode(data, &config)
	})
}
