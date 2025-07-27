package main

//go:generate go run gen.go

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/semihalev/sdns/api"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/server"
	"github.com/semihalev/zlog/v2"
	"github.com/spf13/cobra"
)

const version = "1.6.0"

var (
	cfgPath string
	cfg     *config.Config

	rootCmd = &cobra.Command{
		Use:   "sdns",
		Short: "A high-performance DNS resolver with DNSSEC support",
		Long: `SDNS is a high-performance, recursive DNS resolver server with DNSSEC support,
focused on preserving privacy. For more information, visit https://sdns.dev`,
		RunE: runServer,
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Print the version information",
		Run:   printVersion,
	}
)

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgPath, "config", "c", "sdns.conf", "Location of the config file. If it doesn't exist, a new one will be generated.")
	rootCmd.AddCommand(versionCmd)
}

func setup() error {
	var err error

	if cfg, err = config.Load(cfgPath, version); err != nil {
		return fmt.Errorf("config loading failed: %w", err)
	}

	if cfg.LogLevel == "" {
		cfg.LogLevel = "info"
	}

	// Create structured logger with zero allocations
	logger := zlog.NewStructured()

	// Set log level based on config
	var lvl zlog.Level
	switch cfg.LogLevel {
	case "debug":
		lvl = zlog.LevelDebug
	case "info":
		lvl = zlog.LevelInfo
	case "warn":
		lvl = zlog.LevelWarn
	case "error":
		lvl = zlog.LevelError
	default:
		return fmt.Errorf("log verbosity level unknown: %s", cfg.LogLevel)
	}

	logger.SetLevel(lvl)

	logger.SetWriter(zlog.StdoutTerminal())

	// Set as default logger for global log calls
	zlog.SetDefault(logger)

	middleware.Setup(cfg)
	return nil
}

func runServer(cmd *cobra.Command, args []string) error {
	zlog.Info("Starting sdns...", "version", version)

	if err := setup(); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := server.New(cfg)
	srv.Run(ctx)

	api := api.New(cfg)
	api.Run(ctx)

	// Set up SIGHUP handler for certificate reload
	sigHup := make(chan os.Signal, 1)
	signal.Notify(sigHup, syscall.SIGHUP)
	defer signal.Stop(sigHup)

	go func() {
		for {
			select {
			case <-sigHup:
				zlog.Info("Received SIGHUP, reloading TLS certificate")
				if err := srv.ReloadCertificate(); err != nil {
					zlog.Error("Failed to reload certificate", "error", err.Error())
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	<-ctx.Done()

	zlog.Info("Stopping sdns...")

	// Clean up server resources
	srv.Stop()

	// Graceful shutdown with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	shutdownDone := make(chan struct{})
	go func() {
		for !srv.Stopped() {
			time.Sleep(100 * time.Millisecond)
		}
		close(shutdownDone)
	}()

	select {
	case <-shutdownDone:
		zlog.Info("Server stopped gracefully")
	case <-shutdownCtx.Done():
		zlog.Warn("Server shutdown timeout exceeded")
	}

	return nil
}

func printVersion(cmd *cobra.Command, args []string) {
	buildInfo, _ := debug.ReadBuildInfo()

	settings := make(map[string]string)
	for _, s := range buildInfo.Settings {
		settings[s.Key] = s.Value
	}

	revision := settings["vcs.revision"]
	if len(revision) > 7 {
		revision = revision[:7]
	}

	fmt.Printf("sdns v%s\n", version)
	if revision != "" {
		fmt.Printf("git revision: %s\n", revision)
	}
	fmt.Printf("go version: %s\n", buildInfo.GoVersion)
	fmt.Printf("platform: %s/%s\n", settings["GOOS"], settings["GOARCH"])
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
