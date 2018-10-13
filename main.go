package main

import (
	"flag"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
)

var (
	configPath  string
	forceUpdate bool
	blockCache  = &BlockCache{Backend: make(map[string]bool)}
	localIPs    []string
)

const (
	edns0size = 4096
)

func init() {
	flag.StringVar(&configPath, "config", "sdns.toml", "location of the config file, if not found it will be generated")
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

	if len(Config.RootServers) > 0 {
		rootservers = Config.RootServers
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

	localIPs, err = findLocalIPAddresses()
	if err != nil {
		log.Crit("Local ip addresses failed", "error", err.Error())
	}

	log.Info("Starting sdns...", "version", BuildVersion)

	server := &Server{
		host:           Config.Bind,
		tlsHost:        Config.BindTLS,
		tlsCertificate: Config.TLSCertificate,
		tlsPrivateKey:  Config.TLSPrivateKey,
		rTimeout:       5 * time.Second,
		wTimeout:       5 * time.Second,
	}

	server.Run()

	go func() {
		if err := StartAPIServer(Config.API); err != nil {
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

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGKILL, syscall.SIGTERM)

	<-c

	log.Info("Stopping sdns...")
}
