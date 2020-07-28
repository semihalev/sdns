package config

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/semihalev/log"
)

const configver = "1.1.0"

// Config type
type Config struct {
	Version         string
	BlockLists      []string
	BlockListDir    string
	RootServers     []string
	Root6Servers    []string
	RootKeys        []string
	FallbackServers []string
	AccessList      []string
	LogLevel        string
	AccessLog       string
	Bind            string
	BindTLS         string
	BindDOH         string
	TLSCertificate  string
	TLSPrivateKey   string
	API             string
	Nullroute       string
	Nullroutev6     string
	Hostsfile       string
	OutboundIPs     []string
	OutboundIP6s    []string
	Timeout         Duration
	Expire          uint32
	CacheSize       int
	Maxdepth        int
	RateLimit       int
	ClientRateLimit int
	CookieSecret    string
	NSID            string
	Blocklist       []string
	Whitelist       []string
	Chaos           bool
	QnameMinLevel   int `toml:"qname_min_level"`
	EmptyZones      []string

	Plugins map[string]Plugin

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

# Address to bind to for the DNS server
bind = ":53"

# Address to bind to for the DNS-over-TLS server
# bindtls = ":853"

# Address to bind to for the DNS-over-HTTPS server
# binddoh = ":8053"

# TLS certificate file
# tlscertificate = "server.crt"

# TLS private key file
# tlsprivatekey = "server.key"

# Outbound ipv4 addresses, if you set multiple, sdns can use random outbound ipv4 address by request based
outboundips = [
]

# Outbound ipv6 addresses, if you set multiple, sdns can use random outbound ipv6 address by request based
outboundip6s = [
]

# Root zone ipv4 servers
rootservers = [
"192.5.5.241:53",
"198.41.0.4:53",
"192.228.79.201:53",
"192.33.4.12:53",
"199.7.91.13:53",
"192.203.230.10:53",
"192.112.36.4:53",
"128.63.2.53:53",
"192.36.148.17:53",
"192.58.128.30:53",
"193.0.14.129:53",
"199.7.83.42:53",
"202.12.27.33:53"
]

# Root zone ipv6 servers
root6servers = [
"[2001:500:2f::f]:53",
"[2001:503:ba3e::2:30]:53",
"[2001:500:200::b]:53",
"[2001:500:2::c]:53",
"[2001:500:2d::d]:53",
"[2001:500:a8::e]:53",
"[2001:500:12::d0d]:53",
"[2001:500:1::53]:53",
"[2001:7fe::53]:53",
"[2001:503:c27::2:30]:53",
"[2001:7fd::1]:53",
"[2001:500:9f::42]:53",
"[2001:dc3::35]:53"
]

# Trusted anchors for dnssec
rootkeys = [
".			172800	IN	DNSKEY	257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3+/4RgWOq7HrxRixHlFlExOLAJr5emLvN7SWXgnLh4+B5xQlNVz8Og8kvArMtNROxVQuCaSnIDdD5LKyWbRd2n9WGe2R8PzgCmr3EgVLrjyBxWezF0jLHwVN8efS3rCj/EWgvIWgb9tarpVUDK/b58Da+sqqls3eNbuv7pr+eoZG+SrDK6nWeL3c6H5Apxz7LjVc1uTIdsIXxuOLYA4/ilBmSVIzuDWfdRUfhHdY6+cn8HFRm+2hM8AnXGXws9555KrUB5qihylGa8subX2Nn6UwNR1AkUTV74bU="
]

# Failover resolver ipv4 or ipv6 addresses with port, left blank for disabled. Example: "1.1.1.1:53"
# fallbackservers = [
#	"8.8.8.8:53",
#	"8.8.4.4:53"
# ]
fallbackservers = [
]

# Address to bind to for the http API server, left blank for disabled
api = "127.0.0.1:8080"

# What kind of information should be logged, Log verbosity level [crit,error,warn,info,debug]
loglevel = "info"

# The location of access log file, left blank for disabled. SDNS uses Common Log Format by default.
# accesslog = ""

# List of remote blocklists address list. All lists will be download to blocklist folder.
# blocklists = [
# "http://mirror1.malwaredomains.com/files/justdomains",
# "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
# "http://sysctl.org/cameleon/hosts",
# "https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist",
# "https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt",
# "https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt",
# "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt"
# ]
blocklists = [
]

# List of locations to recursively read blocklists from (warning, every file found is assumed to be a hosts-file or domain list)
blocklistdir = "bl"

# IPv4 address to forward blocked queries to
nullroute = "0.0.0.0"

# IPv6 address to forward blocked queries to
nullroutev6 = "::0"

# Which clients allowed to make queries
accesslist = [
"0.0.0.0/0",
"::0/0"
]

# Enables serving zone data from a hosts file, left blank for disabled
# the form of the entries in the /etc/hosts file are based on IETF RFC 952 which was updated by IETF RFC 1123.
hostsfile = ""

# Network timeout for each dns lookups in duration
timeout = "3s"

# Default error cache TTL in seconds
expire = 600

# Cache size (total records in cache)
cachesize = 256000

# Maximum iteration depth for a query
maxdepth = 30

# Query based ratelimit per second, 0 for disabled
ratelimit = 0

# Client ip address based ratelimit per minute, 0 for disabled
clientratelimit = 0

# Manual blocklist entries
blocklist = []

# Manual whitelist entries
whitelist = []

# DNS server identifier (RFC 5001), it's useful while operating multiple sdns. left blank for disabled
nsid = ""

# Enable to answer version.server, version.bind, hostname.bind, id.server chaos queries.
chaos = true

# Qname minimization level. If higher, it can be more complex and impact the response performance. 
# If set 0, qname minimization will be disable
qname_min_level = 5

# Empty zones return answer for RFC 1918 zones. Please see http://as112.net/
# for details of the problems you are causing and the counter measures that have had to be deployed.
# If the list empty, SDNS will be use default zones described at RFC.
# emptyzones [
#	"10.in-addr.arpa."
# ]
emptyzones = []

# You can add your own plugins to sdns. The plugin order is very important. 
# Plugins can be load before cache middleware.
# Config keys should be string and values can be anything.
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

	log.Info("Loading config file", "path", cfgfile)

	if _, err := toml.DecodeFile(cfgfile, config); err != nil {
		return nil, fmt.Errorf("could not load config: %s", err)
	}

	if config.Version != configver {
		log.Warn("Config file is out of version, you can generate new one and check the changes.")
	}

	config.sVersion = version

	if config.CookieSecret == "" {
		var v uint64

		err := binary.Read(rand.Reader, binary.BigEndian, &v)
		if err != nil {
			return nil, err
		}

		config.CookieSecret = fmt.Sprintf("%16x", v)
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
