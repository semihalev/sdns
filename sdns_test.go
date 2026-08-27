package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigTestReportsOnceWithoutUsage pins what `sdns -t` prints when a
// config is wrong. It used to say the same thing three times — once from the
// test path, once from cobra, once from main — and follow it with the flag
// list, which answers a question nobody asked about a file that is simply
// wrong.
func TestConfigTestReportsOnceWithoutUsage(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sdns.conf")
	body := fmt.Sprintf("version = %q\ndirectory = %q\ndnssec = \"off\"\n"+
		"rootservers = [\"192.5.5.241:53\"]\nnullroute = \"not-an-ip\"\n",
		currentConfigVersion(t), filepath.Join(dir, "db"))
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

// currentConfigVersion reads the version the generator writes, so this test
// does not carry a copy that goes stale on the next bump.
func currentConfigVersion(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gen.conf")
	oldPath, oldTest := cfgPath, testConfig
	defer func() { cfgPath, testConfig = oldPath, oldTest }()

	cfgPath, testConfig = path, true
	_ = validateConfiguration() // generates the file when it is missing

	body, err := os.ReadFile(path) //nolint:gosec // G304 - path is this test's own temp dir
	if err != nil {
		t.Fatalf("generate config: %v", err)
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		if after, ok := strings.CutPrefix(line, "version = "); ok {
			return strings.Trim(strings.TrimSpace(after), "\"")
		}
	}
	t.Fatal("generated config has no version")
	return ""
}
