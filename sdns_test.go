package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/semihalev/zlog/v2"
)

// TestConfigTestReportsOnceWithoutUsage pins what `sdns -t` prints when a
// config is wrong. It used to say the same thing three times, once from the
// test path, once from cobra, once from main, and follow it with the flag
// list, which answers a question nobody asked about a file that is simply
// wrong.
func TestConfigTestReportsOnceWithoutUsage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf("directory = %q\ndnssec = \"off\"\n"+
		"rootservers = [\"192.5.5.241:53\"]\nnullroute = \"not-an-ip\"\n",
		filepath.Join(dir, "db"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPath, oldTest, oldCfg := cfgPath, testConfig, cfg
	// runServer silences usage on the shared command; the binary exits right
	// after, but a test leaves it set for whatever runs next.
	oldSilence := rootCmd.SilenceUsage
	defer func() {
		cfgPath, testConfig, cfg = oldPath, oldTest, oldCfg
		rootCmd.SilenceUsage = oldSilence
	}()

	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"-c", path, "-t"})
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
	}()

	err := rootCmd.Execute()
	if err == nil {
		t.Fatal("Execute() accepted a config with an unusable value")
	}
	if !strings.Contains(err.Error(), "nullroute") {
		t.Fatalf("Execute() = %v, want the problem named", err)
	}

	got := out.String()
	if strings.Contains(got, "Usage:") {
		t.Fatalf("a wrong config printed the flag list:\n%s", got)
	}
	if n := strings.Count(got, "nullroute"); n != 0 {
		// main is the only printer; cobra must stay quiet.
		t.Fatalf("cobra printed the error itself %d time(s):\n%s", n, got)
	}
}

func TestConfigTestWarnsWhenCacheExceedsMemoryBudget(t *testing.T) {
	oldMemoryLimit := debug.SetMemoryLimit(1 << 30)
	defer debug.SetMemoryLimit(oldMemoryLimit)

	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\n"+
		"rootservers = [\"192.5.5.241:53\"]\ncachesize = 1000000\n",
		version, filepath.Join(dir, "db"))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}

	oldPath, oldCfg := cfgPath, cfg
	oldLogger := zlog.Default()
	defer func() {
		cfgPath, cfg = oldPath, oldCfg
		zlog.SetDefault(oldLogger)
	}()

	var logOutput bytes.Buffer
	logger := zlog.NewStructured()
	logger.SetLevel(zlog.LevelWarn)
	logger.SetWriter(&logOutput)
	zlog.SetDefault(logger)

	cfgPath = path
	if err := validateConfiguration(); err != nil {
		t.Fatalf("validateConfiguration() = %v", err)
	}
	for _, part := range []string{"cachesize", "full occupancy", "memory budget"} {
		if !strings.Contains(logOutput.String(), part) {
			t.Errorf("config-test log %q does not contain %q", logOutput.String(), part)
		}
	}
}

// TestUsageErrorStillPrintsUsage pins the other half: usage is silenced for a
// bad configuration, not for a bad command line.
func TestUsageErrorStillPrintsUsage(t *testing.T) {
	var out bytes.Buffer
	oldSilence := rootCmd.SilenceUsage
	rootCmd.SilenceUsage = false
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetArgs([]string{"--nosuchflag"})
	defer func() {
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
		rootCmd.SetArgs(nil)
		rootCmd.SilenceUsage = oldSilence
	}()

	if err := rootCmd.Execute(); err == nil {
		t.Fatal("Execute() accepted an unknown flag")
	}
	if !strings.Contains(out.String(), "Usage:") {
		t.Fatalf("an unknown flag did not print the flag list:\n%s", out.String())
	}
}

// TestShutdownDrainBudget pins how long a stop waits for in-flight queries.
// The process used to give up after a fixed 10 seconds, so querytimeout of
// 30s dropped a query whose upstream answered at 20s. Zero stays 10 seconds,
// the same default as an omitted or "0" querytimeout, and a shorter positive
// value is not raised to that old cap.
func TestShutdownDrainBudget(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   time.Duration
		want time.Duration
	}{
		{name: "reported config", in: 30 * time.Second, want: 30 * time.Second},
		{name: "omitted or zero", in: 0, want: 10 * time.Second},
		{name: "shorter than the old cap", in: time.Second, want: time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := shutdownDrainBudget(tc.in); got != tc.want {
				t.Fatalf("shutdownDrainBudget(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
