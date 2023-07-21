package main

//go:generate go run gen.go

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
)

const version = "1.3.1-rc1"

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

func run(ctx context.Context) *server.Server {
	srv := server.New(cfg)
	srv.Run(ctx)

	api := api.New(cfg)
	api.Run(ctx)

	return srv
}

func main() {
	flag.Parse()

	if *flagprintver {
		println("SDNS v" + version)
		os.Exit(0)
	}

	log.Info("Starting sdns...", "version", version)

	setup()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	srv := run(ctx)

	<-ctx.Done()

	log.Info("Stopping sdns...")

	stop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for !srv.Stopped() {
		select {
		case <-time.After(100 * time.Millisecond):
			continue
		case <-ctx.Done():
			return
		}
	}
}
