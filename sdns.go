package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware/accesslist"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/sdns/middleware/cache"
	"github.com/semihalev/sdns/middleware/hostsfile"
	"github.com/semihalev/sdns/middleware/metrics"
	"github.com/semihalev/sdns/middleware/ratelimit"
	"github.com/semihalev/sdns/middleware/recovery"
	"github.com/semihalev/sdns/middleware/resolver"
	"github.com/semihalev/sdns/server"
)

var (
	// Config is the global configuration
	Config *config.Config

	// Version returns the build version of sdns, this should be incremented every new release
	Version = "0.2.4-rc1"

	// ConfigVersion returns the version of sdns, this should be incremented every time the config changes so sdns presents a warning
	ConfigVersion = "0.2.4"

	// ConfigPath returns the configuration path
	ConfigPath = flag.String("config", "sdns.toml", "location of the config file, if not found it will be generated")

	// Usage return print usage information
	Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "OPTIONS:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "USAGE:")
		fmt.Fprintln(os.Stderr, "./sdns -config=sdns.toml")
		fmt.Fprintln(os.Stderr, "")
	}
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Usage = Usage
}

func setup() {
	var err error

	if Config, err = config.Load(*ConfigPath, ConfigVersion); err != nil {
		log.Crit("Config loading failed", "error", err.Error())
	}

	lvl, err := log.LvlFromString(Config.LogLevel)
	if err != nil {
		log.Crit("Log verbosity level unknown")
	}

	log.Root().SetLevel(lvl)
	log.Root().SetHandler(log.LvlFilterHandler(lvl, log.StdoutHandler))

	if Config.Timeout.Duration < 250*time.Millisecond {
		Config.Timeout.Duration = 250 * time.Millisecond
	}

	if Config.ConnectTimeout.Duration < 250*time.Millisecond {
		Config.ConnectTimeout.Duration = 250 * time.Millisecond
	}

	if Config.CacheSize < 1024 {
		Config.CacheSize = 1024
	}
}

func run() {
	server := server.New(Config)

	// register middlewares
	server.Register(&recovery.Recovery{})

	metrics := metrics.New(Config)
	server.Register(metrics)

	accesslist := accesslist.New(Config)
	server.Register(accesslist)

	ratelimit := ratelimit.New(Config)
	server.Register(ratelimit)

	hostsfile := hostsfile.New(Config)
	server.Register(hostsfile)

	blocklist := blocklist.New(Config)
	server.Register(blocklist)

	cache := cache.New(Config)
	server.Register(cache)

	resolver := resolver.New(Config, cache)
	server.Register(resolver)

	server.Run()

	api := api.New(Config.API, blocklist)
	api.Run()

	go fetchBlocklists(blocklist)
}

func main() {
	flag.Parse()

	log.Info("Starting sdns...", "version", Version)

	setup()
	run()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Info("Stopping sdns...")
}
