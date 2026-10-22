package config

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"
)

// writeMinimal writes the smallest file the gate accepts, plus extra, and
// returns its path and the state directory it names.
func writeMinimal(t *testing.T, extra string) (path, dir string) {
	t.Helper()
	root := t.TempDir()
	dir = filepath.Join(root, "db")
	path = filepath.Join(root, "sdns.conf")
	content := "directory = " + quote(dir) + "\ndnssec = \"off\"\nrootservers = [\"192.0.2.1:53\"]\n" + extra
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, dir
}

func quote(s string) string { return "'" + s + "'" }

// A reload judges the file on disk and nothing else: Parse never writes a
// file, never creates the state directory, never invents a cookie secret,
// and a missing file is an error rather than a fresh default.
func TestParseWritesNothing(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.conf")
	if _, err := Parse(missing, nil); err == nil {
		t.Fatal("a missing file parsed")
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("Parse generated the missing file")
	}

	path, dir := writeMinimal(t, "")
	cfg, err := Parse(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("Parse created the state directory")
	}
	if cfg.CookieSecret != "" {
		t.Fatal("Parse generated a cookie secret")
	}
}

// IPv6 access is settled before the gate, which judges root6servers and
// outboundip6s by it, and the question is asked only when the file leaves
// it off.
func TestParseAsksForIPv6OnlyWhenTheFileLeavesItOff(t *testing.T) {
	asked := 0
	yes := func() bool { asked++; return true }

	path, _ := writeMinimal(t, "ipv6access = true\n")
	if _, err := Parse(path, yes); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if asked != 0 {
		t.Fatal("asked about IPv6 for a file that already turns it on")
	}

	path, _ = writeMinimal(t, "")
	cfg, err := Parse(path, yes)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if asked != 1 || !cfg.IPv6Access {
		t.Fatalf("asked %d times, IPv6Access %v; want one question and access on", asked, cfg.IPv6Access)
	}
}

// Startup with ipv6access = true must not pay the probe's round trip.
func TestLoadDoesNotProbeWhenTheFileSaysIPv6(t *testing.T) {
	original := ipv6Probe
	defer func() { ipv6Probe = original }()
	probed := false
	ipv6Probe = func() error { probed = true; return nil }

	path, _ := writeMinimal(t, "ipv6access = true\n")
	if _, err := Load(path, "test"); err != nil {
		t.Fatalf("load: %v", err)
	}
	if probed {
		t.Fatal("Load probed IPv6 for a file that already turns it on")
	}
}

// The values handlers would otherwise fill in are settled by Parse, so the
// configuration a reload compares against is the one that is running.
func TestParseSettlesHandlerDefaults(t *testing.T) {
	path, dir := writeMinimal(t, "")
	cfg, err := Parse(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("loglevel = %q, want info", cfg.LogLevel)
	}
	if !slices.Equal(cfg.Bind, Addrs{":53"}) {
		t.Errorf("bind = %v, want [:53]", cfg.Bind)
	}
	if !slices.Equal(cfg.AccessList, []string{"0.0.0.0/0", "::0/0"}) {
		t.Errorf("accesslist = %v, want everyone", cfg.AccessList)
	}
	if cfg.BlockListDir != filepath.Join(dir, "blacklists") {
		t.Errorf("blocklistdir = %q, want it under directory", cfg.BlockListDir)
	}
	if cfg.Maxdepth != 30 {
		t.Errorf("maxdepth = %d, want 30", cfg.Maxdepth)
	}
	if cfg.QueryTimeout.Duration != 10*time.Second {
		t.Errorf("querytimeout = %v, want 10s", cfg.QueryTimeout.Duration)
	}
}

// Load is Parse plus its side effects and nothing else, so startup, sdns -t
// and a reload all read a file the same way.
func TestLoadIsParsePlusSideEffects(t *testing.T) {
	original := ipv6Probe
	defer func() { ipv6Probe = original }()
	ipv6Probe = func() error { return nil }

	path, _ := writeMinimal(t, "")
	loaded, err := Load(path, "test")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	parsed, err := Parse(path, func() bool { return true })
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	loaded.CookieSecret, loaded.sVersion = "", ""
	if !reflect.DeepEqual(loaded, parsed) {
		t.Fatalf("Load and Parse disagree:\nload  %+v\nparse %+v", loaded, parsed)
	}
}

// Unknown keys are recorded for the caller to judge: startup warns, sdns -t
// and a reload refuse.
func TestParseRecordsUnknownKeys(t *testing.T) {
	path, _ := writeMinimal(t, "nosuchkey = 1\n")
	cfg, err := Parse(path, nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !slices.Equal(cfg.UndecodedKeys(), []string{"nosuchkey"}) {
		t.Fatalf("unknown keys = %v, want [nosuchkey]", cfg.UndecodedKeys())
	}
}
