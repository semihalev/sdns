package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/yl2chen/cidranger"
)

var (
	configPath  string
	forceUpdate bool
	blockCache  = &BlockCache{Backend: make(map[string]bool)}
	localIPs    []string
	accessList  cidranger.Ranger
)

func init() {
	flag.StringVar(&configPath, "config", "sdns.toml", "location of the config file, if not found it will be generated")
	flag.Usage = usage
}

func usage() {
	fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "OPTIONS:")
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "USAGE:")
	fmt.Fprintln(os.Stderr, "./sdns -config=sdns.toml")
	fmt.Fprintln(os.Stderr, "")
}

func startSDNS() {
	if len(Config.RootServers) > 0 {
		rootservers = []*AuthServer{}
		for _, s := range Config.RootServers {
			rootservers = append(rootservers, &AuthServer{Host: s, RTT: time.Hour})
		}
	}

	if len(Config.Root6Servers) > 0 {
		root6servers = []*AuthServer{}
		for _, s := range Config.Root6Servers {
			root6servers = append(root6servers, &AuthServer{Host: s, RTT: time.Hour})
		}
	}

	if len(Config.FallbackServers) > 0 {
		fallbackservers = []*AuthServer{}
		for _, s := range Config.FallbackServers {
			fallbackservers = append(fallbackservers, &AuthServer{Host: s, RTT: time.Hour})
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

	var err error

	localIPs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Local ip addresses failed", "error", err.Error())
	}

	accessList = cidranger.NewPCTrieRanger()
	for _, cidr := range Config.AccessList {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Crit("Access list parse cidr failed", "error", err.Error())
		}

		err = accessList.Insert(cidranger.NewBasicRangerEntry(*ipnet))
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
		us := make(chan os.Signal, 1)
		signal.Notify(us, syscall.SIGUSR1)

		timer := time.NewTimer(time.Second)

		for {
			select {
			case <-timer.C:
				if err := updateBlocklists(Config.BlockListDir); err != nil {
					log.Error("Update blocklists failed", "error", err.Error())
				}

				if err := readBlocklists(Config.BlockListDir); err != nil {
					log.Error("Read blocklists failed", "dir", Config.BlockListDir, "error", err.Error())
				}
			case <-us:
				if err := updateBlocklists(Config.BlockListDir); err != nil {
					log.Error("Update blocklists failed", "error", err.Error())
				}

				if err := readBlocklists(Config.BlockListDir); err != nil {
					log.Error("Read blocklists failed", "dir", Config.BlockListDir, "error", err.Error())
				}
			}
		}
	}()
}

func main() {
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())

	if err := LoadConfig(configPath); err != nil {
		log.Crit("Config loading failed", "error", err.Error())
	}

	lvl, err := log.LvlFromString(Config.LogLevel)
	if err != nil {
		log.Crit("Log verbosity level unknown")
	}

	log.Root().SetHandler(log.LvlFilterHandler(lvl, log.StdoutHandler))

	log.Info("Starting sdns...", "version", BuildVersion)

	startSDNS()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)

	<-c

	log.Info("Stopping sdns...")
}
