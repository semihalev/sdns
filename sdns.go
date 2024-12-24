package main

//go:generate go run gen.go

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
)

const version = "1.4.0"

var (
	flagcfgpath  string
	flagprintver bool

	cfg *config.Config
)

func init() {
	flag.StringVar(&flagcfgpath, "config", "sdns.conf", "Location of the config file. If it doesn't exist, a new one will be generated.")
	flag.StringVar(&flagcfgpath, "c", "sdns.conf", "Location of the config file. If it doesn't exist, a new one will be generated.")

	flag.BoolVar(&flagprintver, "version", false, "Show the version of the sdns.")
	flag.BoolVar(&flagprintver, "v", false, "Show the version of the sdns.")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n  sdns [OPTIONS]\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		fmt.Fprintf(os.Stderr, "  -c, --config PATH\tLocation of the config file. If it doesn't exist, a new one will be generated.\n")
		fmt.Fprintf(os.Stderr, "  -v, --version\t\tShow the version of the sdns and exit.\n")
		fmt.Fprintf(os.Stderr, "  -h, --help\t\tShow this help and exit.\n\n")
		fmt.Fprintf(os.Stderr, "Example:\n")
		fmt.Fprintf(os.Stderr, "  sdns -c sdns.conf\n\n")
	}
}

func setup() {
	var err error

	if cfg, err = config.Load(flagcfgpath, version); err != nil {
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

func printver() {
	buildInfo, _ := debug.ReadBuildInfo()

	settings := make(map[string]string)
	for _, s := range buildInfo.Settings {
		settings[s.Key] = s.Value
	}

	fmt.Fprintf(os.Stderr, "sdns v%s rev %.7s\nbuilt by %s (%s %s)\n", version,
		settings["vcs.revision"], buildInfo.GoVersion, settings["GOOS"], settings["GOARCH"])

	os.Exit(0)
}

func main() {
	flag.Parse()

	if flagprintver {
		printver()
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
