package main

//go:generate go run gen.go

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
)

var (
	// Version returns the build version of sdns, this should be incremented every new release
	Version = "1.1.2"

	// ConfigVersion returns the version of sdns, this should be incremented every time the config changes so sdns presents a warning
	ConfigVersion = "1.1.0"

	// ConfigPath returns the configuration path
	ConfigPath = flag.String("config", "sdns.conf", "location of the config file, if config file not found, a config will generate")

	// VersionFlag returns of the flag of version
	VersionFlag = flag.Bool("v", false, "show version information")

	// Usage return print usage information
	Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Example:")
		fmt.Fprintf(os.Stderr, "%s -config=sdns.conf\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "")
	}
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())
	flag.Usage = Usage
}

func setup() {
	var err error

	if cfg, err = config.Load(*ConfigPath, ConfigVersion, Version); err != nil {
		log.Crit("Config loading failed", "error", err.Error())
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	lvl, err := log.LvlFromString(cfg.LogLevel)
	if err != nil {
		log.Crit("Log verbosity level unknown")
	}

	log.Root().SetLevel(lvl)
	log.Root().SetHandler(log.LvlFilterHandler(lvl, log.StdoutHandler))

	middleware.Setup(cfg)
}

func run() {
	server := server.New(cfg)
	server.Run()

	api := api.New(cfg)
	api.Run()
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

var cfg *config.Config
