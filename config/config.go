package config

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

const configver = "1.4.0"

// Config type
type Config struct {
	Version          string
	Directory        string
	BlockLists       []string
	BlockListDir     string
	RootServers      []string
	Root6Servers     []string
	DNSSEC           string
	RootKeys         []string
	FallbackServers  []string
	ForwarderServers []string
	AccessList       []string
	LogLevel         string
	AccessLog        string
	Bind             string
	BindTLS          string
	BindDOH          string
	BindDOQ          string
	TLSCertificate   string
	TLSPrivateKey    string
	API              string
	BearerToken      string
	Nullroute        string
	Nullroutev6      string
	Hostsfile        string
	OutboundIPs      []string
	OutboundIP6s     []string
	Timeout          Duration
	QueryTimeout     Duration
	Expire           uint32
	CacheSize        int
	Prefetch         uint32
	Maxdepth         int
	RateLimit        int
	ClientRateLimit  int
	NSID             string
	Blocklist        []string
	Whitelist        []string
	Chaos            bool
	QnameMinLevel    int `toml:"qname_min_level"`
	EmptyZones       []string

	Plugins map[string]Plugin

	CookieSecret string
	IPv6Access   bool

	sVersion string
}

// Plugin type
type Plugin struct {
	Path   string
	Config map[string]interface{}
}

// ServerVersion return current server version
func (c *Config) ServerVersion() string {
	return c.sVersion
}

// Duration type
type Duration struct {
	time.Duration
}

// UnmarshalText for duration type
func (d *Duration) UnmarshalText(text []byte) error {
	var err error
	d.Duration, err = time.ParseDuration(string(text))
	return err
}

var defaultConfig = `
# Config version, config and build versions can be different.
version = "%s"

# Sets the sdns working directory. The directory must have write access for sdns's user.
directory = "db"

# Address to bind to for the DNS server.
bind = ":53"

# Address to bind to for the DNS-over-TLS server.
# bindtls = ":853"

# Address to bind to for the DNS-over-HTTPS server.
# binddoh = ":443"

# Address to bind to for the DNS-over-QUIC server.
# binddoq = ":853"

# TLS certificate file.
# tlscertificate = "server.crt"

# TLS private key file.
# tlsprivatekey = "server.key"

# Outbound IPv4 addresses, if you set multiple, sdns can use a random outbound IPv4 address by request based.
outboundips = [
]

# Outbound IPv6 addresses, if you set multiple, sdns can use a random outbound IPv6 address by request based.
outboundip6s = [
]

# Root zone IPv4 servers
rootservers = [
    "198.41.0.4:53",
    "199.9.14.201:53",
    "192.33.4.12:53",
    "199.7.91.13:53",
    "192.203.230.10:53",
    "192.5.5.241:53",
    "192.112.36.4:53",
    "198.97.190.53:53",
    "192.36.148.17:53",
    "192.58.128.30:53",
    "193.0.14.129:53",
    "199.7.83.42:53",
    "202.12.27.33:53"
]

# Root zone IPv6 servers
root6servers = [
    "[2001:503:ba3e::2:30]:53",
    "[2001:500:200::b]:53",
    "[2001:500:2::c]:53",
    "[2001:500:2d::d]:53",
    "[2001:500:a8::e]:53",
    "[2001:500:2f::f]:53",
    "[2001:500:12::d0d]:53",
    "[2001:500:1::53]:53",
    "[2001:7fe::53]:53",
    "[2001:503:c27::2:30]:53",
    "[2001:7fd::1]:53",
    "[2001:500:9f::42]:53",
    "[2001:dc3::35]:53"
]

# DNSSEC validation on signed zones, off for disabled.
dnssec = "on"

# Trusted anchors for DNSSEC.
rootkeys = [
    ".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU=",
	".			172800	IN	DNSKEY	257	3 8	AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc="
]

# Failover resolver IPv4 or IPv6 addresses with port, left blank for disabled.
# fallbackservers = [
#   "8.8.8.8:53",
#   "[2001:4860:4860::8888]:53"
# ]
fallbackservers = [
]

# Forwarder resolver IPv4 or IPv6 addresses with port, left blank for disabled.
# forwarderservers = [
#   "8.8.8.8:53",
#   "[2001:4860:4860::8888]:53",
#   "tls://8.8.8.8:853"
# ]
forwarderservers = [
]

# Address to bind to for the HTTP API server, left blank for disabled.
api = "127.0.0.1:8080"

# API bearer token for authorization. If the token set, Authorization header should be send on API requests.
# Header: Authorization: Bearer %%bearertoken%%
# bearertoken = ""

# What kind of information should be logged, Log verbosity level [crit, error, warn, info, debug].
loglevel = "info"

# The location of the access log file, left blank for disabled. SDNS uses Common Log Format by default.
# accesslog = ""

# List of remote blocklists address list. All lists will be downloaded to the blocklist folder.
# blocklists = [
#    "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
#    "http://sysctl.org/cameleon/hosts",
#    "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
#    "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt"
# ]
blocklists = [
]

# [DEPRECATED] This will be ignored. The directory will be created under the working directory automatically.
blocklistdir = ""

# IPv4 address to forward blocked queries to.
nullroute = "0.0.0.0"

# IPv6 address to forward blocked queries to.
nullroutev6 = "::0"

# Which clients are allowed to make queries.
accesslist = [
    "0.0.0.0/0",
    "::0/0"
]

# Enables serving zone data from a hosts file, left blank for disabled.
# The form of the entries in the /etc/hosts file is based on IETF RFC 952, which was updated by IETF RFC 1123.
hostsfile = ""

# Specifies the network timeout duration for each DNS lookup.
timeout = "2s"

# Defines the maximum duration to wait for each DNS query to respond.
querytimeout = "10s"

# Default error cache TTL in seconds.
expire = 600

# Cache size (total records in cache).
cachesize = 256000

# Cache prefetch before expire. The default threshold is 10%%, 0 for disabled. 
# The threshold percent should be between 10%% ~ 90%%.
prefetch = 10

# Maximum iteration depth for a query.
maxdepth = 30

# Query-based ratelimit per second, 0 for disabled.
ratelimit = 0

# Client IP address-based ratelimit per minute, 0 for disabled.
clientratelimit = 0

# Manual blocklist entries.
# blocklist = [
#   "example.com",
#   "example.net"
# ]
blocklist = [
]

# Whitelist entries.
# whitelist = [
#   "example.com",
#   "example.net"
# ]
whitelist = [
]

# DNS server identifier (RFC 5001), it's useful while operating multiple sdns. Left blank for disabled.
nsid = ""

# Enable to answer version.server, version.bind, hostname.bind, id.server chaos queries.
chaos = true

# Qname minimization level. If higher, it can be more complex and impact the response performance. 
# If set to 0, qname minimization will be disabled.
qname_min_level = 5

# Empty zones return an answer for RFC 1918 zones. Please see http://as112.net/
# for details of the problems you are causing and the countermeasures that have had to be deployed.
# If the list is empty, SDNS will use default zones described at RFC.
# emptyzones = [
#   "10.in-addr.arpa."
# ]
emptyzones = [
]

# You can add your own plugins to sdns. The plugin order is very important. 
# Plugins can be loaded before the cache middleware.
# Config keys should be strings, and values can be anything.
# There is an example plugin at https://github.com/semihalev/sdnsexampleplugin
# [plugins]
#     [plugins.example]
#     path = "exampleplugin.so"
#     config = {key_1 = "value_1", key_2 = 2, key_3 = true}
`

// Load loads the given config file
func Load(cfgfile, version string) (*Config, error) {
	config := new(Config)

	if _, err := os.Stat(cfgfile); os.IsNotExist(err) {
		if path.Base(cfgfile) == "sdns.conf" {
			// compatibility for old default conf file
			if _, err := os.Stat("sdns.toml"); os.IsNotExist(err) {
				if err := generateConfig(cfgfile); err != nil {
					return nil, err
				}
			} else {
				cfgfile = "sdns.toml"
			}
		}
	}

	log.Info("Loading config file...", "path", cfgfile)

	if _, err := toml.DecodeFile(cfgfile, config); err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}

	if config.Version != configver {
		log.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	if _, err := os.Stat(config.Directory); os.IsNotExist(err) {
		if err := os.Mkdir(config.Directory, 0750); err != nil {
			return nil, fmt.Errorf("error creating working directory: %s", err)
		}
	}

	log.Info("Working directory", "path", config.Directory)

	config.sVersion = version

	if config.DNSSEC == "" || config.DNSSEC != "off" {
		config.DNSSEC = "on"
	}

	if config.CookieSecret == "" {
		var v uint64

		err := binary.Read(rand.Reader, binary.BigEndian, &v)
		if err != nil {
			return nil, err
		}

		config.CookieSecret = fmt.Sprintf("%16x", v)
	}

	if !config.IPv6Access {
		err := testIPv6Network()
		if err == nil {
			config.IPv6Access = true
		}
	}

	return config, nil
}

func generateConfig(path string) error {
	output, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("could not generate config: %s", err)
	}

	defer func() {
		err := output.Close()
		if err != nil {
			log.Warn("Config generation failed while file closing", "error", err.Error())
		}
	}()

	r := strings.NewReader(fmt.Sprintf(defaultConfig, configver))
	if _, err := io.Copy(output, r); err != nil {
		return fmt.Errorf("could not copy default config: %s", err)
	}

	if abs, err := filepath.Abs(path); err == nil {
		log.Info("Default config file generated", "config", abs)
	}

	return nil
}

func testIPv6Network() error {
	client := &dns.Client{Net: "udp"}

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)

	//root server
	_, _, err := client.Exchange(req, net.JoinHostPort("2001:500:2::c", "53"))
	if err != nil {
		return err
	}

	return nil
}
