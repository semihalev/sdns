package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/yl2chen/cidranger"
)

var (
	// Config is the global configuration
	Config config

	// Version returns the build version of sdns, this should be incremented every new release
	Version = "0.2.1-rc2"

	// ConfigVersion returns the version of sdns, this should be incremented every time the config changes so sdns presents a warning
	ConfigVersion = "0.1.9"

	// ConfigPath returns the configuration path
	ConfigPath = flag.String("config", "sdns.toml", "location of the config file, if not found it will be generated")

	// LocalIPs returns list of local ip addresses
	LocalIPs []string

	// AccessList returns created CIDR rangers
	AccessList cidranger.Ranger

	// BlockList returns BlockCache
	BlockList = cache.NewBlockCache()
)

func init() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "OPTIONS:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "USAGE:")
		fmt.Fprintln(os.Stderr, "./sdns -config=sdns.toml")
		fmt.Fprintln(os.Stderr, "")
	}
}

func startSDNS() {
	if len(Config.RootServers) > 0 {
		rootservers = []*cache.AuthServer{}
		for _, s := range Config.RootServers {
			rootservers = append(rootservers, cache.NewAuthServer(s))
		}
	}

	if len(Config.Root6Servers) > 0 {
		root6servers = []*cache.AuthServer{}
		for _, s := range Config.Root6Servers {
			root6servers = append(root6servers, cache.NewAuthServer(s))
		}
	}

	if len(Config.FallbackServers) > 0 {
		fallbackservers = []*cache.AuthServer{}
		for _, s := range Config.FallbackServers {
			fallbackservers = append(fallbackservers, cache.NewAuthServer(s))
		}
	}

	if len(Config.RootKeys) > 0 {
		initialkeys = Config.RootKeys
		rootkeys = []dns.RR{}

		for _, k := range initialkeys {
			rr, err := dns.NewRR(k)
			if err != nil {
				log.Crit("Root keys invalid", "error", err.Error())
			}
			rootkeys = append(rootkeys, rr)
		}
	}

	if Config.Interval < 200 {
		Config.Interval = 200
	}

	var err error

	LocalIPs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Local ip addresses failed", "error", err.Error())
	}

	AccessList = cidranger.NewPCTrieRanger()
	for _, cidr := range Config.AccessList {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Crit("Access list parse cidr failed", "error", err.Error())
		}

		err = AccessList.Insert(cidranger.NewBasicRangerEntry(*ipnet))
		if err != nil {
			log.Crit("Access list insert cidr failed", "error", err.Error())
		}
	}

	server := &Server{
		host:           Config.Bind,
		tlsHost:        Config.BindTLS,
		dohHost:        Config.BindDOH,
		tlsCertificate: Config.TLSCertificate,
		tlsPrivateKey:  Config.TLSPrivateKey,
		rTimeout:       5 * time.Second,
		wTimeout:       5 * time.Second,
	}

	server.Run()

	go func() {
		if err := runAPIServer(Config.API); err != nil {
			log.Crit("Start API server failed", "error", err.Error())
		}
	}()

	go func() {
		timer := time.NewTimer(time.Second)

		select {
		case <-timer.C:
			if err := updateBlocklists(Config.BlockListDir); err != nil {
				log.Error("Update blocklists failed", "error", err.Error())
			}

			if err := readBlocklists(Config.BlockListDir); err != nil {
				log.Error("Read blocklists failed", "dir", Config.BlockListDir, "error", err.Error())
			}
		}
	}()
}

func main() {
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())

	if err := LoadConfig(*ConfigPath); err != nil {
		log.Crit("Config loading failed", "error", err.Error())
	}

	lvl, err := log.LvlFromString(Config.LogLevel)
	if err != nil {
		log.Crit("Log verbosity level unknown")
	}

	log.Root().SetHandler(log.LvlFilterHandler(lvl, log.StdoutHandler))

	log.Info("Starting sdns...", "version", Version)

	startSDNS()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Info("Stopping sdns...")
}
