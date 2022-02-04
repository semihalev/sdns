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

const version = "1.2.1"

var (
	flagcfgpath  = flag.String("config", "sdns.conf", "location of the config file, if config file not found, a config will generate")
	flagprintver = flag.Bool("v", false, "show version information")

	cfg *config.Config
)

func init() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "Example:")
		fmt.Fprintf(os.Stderr, "%s -config=sdns.conf\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "")
	}
}

func setup() {
	var err error

	if cfg, err = config.Load(*flagcfgpath, version); err != nil {
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

	if *flagprintver {
		println("SDNS v" + version)
		os.Exit(0)
	}

	log.Info("Starting sdns...", "version", version)

	setup()
	run()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c

	log.Info("Stopping sdns...")
}
