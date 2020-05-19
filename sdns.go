package main

//go:generate go run gen.go

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
)

var (
	// Config is the global configuration
	Config *config.Config

	// Version returns the build version of sdns, this should be incremented every new release
	Version = "1.0.0-rc2"

	// ConfigVersion returns the version of sdns, this should be incremented every time the config changes so sdns presents a warning
	ConfigVersion = "1.0.0"

	// ConfigPath returns the configuration path
	ConfigPath = flag.String("config", "sdns.conf", "location of the config file, if not found it will be generated")

	// VersionFlag returns of the flag of version
	VersionFlag = flag.Bool("v", false, "version information")

	// Usage return print usage information
	Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "OPTIONS:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "USAGE:")
		fmt.Fprintln(os.Stderr, "./sdns -config=sdns.conf")
		fmt.Fprintln(os.Stderr, "")
	}
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Usage = Usage
}

func setup() {
	var err error

	if Config, err = config.Load(*ConfigPath, ConfigVersion, Version); err != nil {
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

	if Config.CacheSize < 1024 {
		Config.CacheSize = 1024
	}

	if Config.CookieSecret == "" {
		Config.CookieSecret = fmt.Sprintf("%16x", rand.Int63())
	}
}

func run() {
	middleware.Setup(Config)

	for i, h := range middleware.Handlers() {
		log.Debug("Middleware registered", "name", h.Name(), "index", i)
	}

	server := server.New(Config)
	server.Run()

	api := api.New(Config)
	api.Run()

	go fetchBlocklists()
}

func main() {
	flag.Parse()

	if *VersionFlag {
		println("SDNS v" + Version)
		os.Exit(0)
	}

	log.Info("Starting sdns...", "version", Version)

	setup()
	run()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Info("Stopping sdns...")
}
