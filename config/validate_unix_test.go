//go:build unix

package config

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestValidateRejectsSpecialFiles lives here because syscall.Mkfifo does not
// exist on Windows — a runtime skip would still fail to build there.
func TestValidateRejectsSpecialFiles(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	// Not a directory, and still not something to read a hosts file from —
	// opening it would block startup rather than fail.
	if err := (&Config{HostsFile: fifo}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "named pipe") {
		t.Fatalf("Validate() = %v, want the FIFO rejected", err)
	}
}

// These two turn on POSIX file modes. Windows does not enforce them the same
// way, and os.Getuid there returns -1, so a runtime root check would not skip
// either — hence the build tag rather than a skip.

func TestValidateUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads regardless of mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts")
	if err := os.WriteFile(path, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	// A regular file, and still not one this process can read — every
	// consumer here opens it, so the type test alone was not enough.
	if err := (&Config{HostsFile: path}).Validate(); err == nil {
		t.Fatal("Validate() accepted a file it cannot read")
	}
}

func TestValidateUnwritableAccessLog(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes regardless of mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "ro.log")
	if err := os.WriteFile(path, []byte(""), 0o400); err != nil {
		t.Fatal(err)
	}
	// Opened write-only; the middleware logs the failure and carries on with
	// access logging quietly switched off.
	if err := (&Config{AccessLog: path}).Validate(); err == nil {
		t.Fatal("Validate() accepted an access log it cannot write")
	}
}

func TestValidateUnwritableExistingDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes regardless of mode")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "db")
	if err := os.Mkdir(target, 0o500); err != nil { //nolint:gosec // G301 - the point is a directory that cannot be written
		t.Fatal(err)
	}
	// Put write back so t.TempDir can clean up.
	defer os.Chmod(target, 0o700) //nolint:errcheck,gosec // test cleanup

	// The directory is there and is a directory; mode bits alone do not say
	// whether this process can write in it, so the check creates an entry and
	// takes it back out.
	if err := (&Config{Directory: target}).Validate(); err == nil {
		t.Fatal("Validate() accepted a working directory it cannot write in")
	}
}

func TestValidateSymlinkToUnwritableDirectory(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes regardless of mode")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "db")
	if err := os.Mkdir(target, 0o500); err != nil { //nolint:gosec // G301 - the point is a directory that cannot be written
		t.Fatal(err)
	}
	defer os.Chmod(target, 0o700) //nolint:errcheck,gosec // test cleanup

	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	// Named directly it is refused; through a link it has to be refused too,
	// since that is the path the server writes to.
	if err := (&Config{Directory: link}).Validate(); err == nil {
		t.Fatal("Validate() accepted a symlink to a directory it cannot write in")
	}
}

// TestValidatePathsKeepTheirComponents pins the unix rule. A path is resolved
// one component at a time here, so "missing/../x" fails on the "missing" that
// is not there — while filepath.Dir cleans it away and would call the path
// perfectly fine. Windows collapses ".." itself, so this is not its rule and
// the test does not run there.
func TestValidatePathsKeepTheirComponents(t *testing.T) {
	dir := t.TempDir()
	// Built by hand: filepath.Join cleans too.
	logPath := dir + "/missing/../access.log"
	if err := (&Config{AccessLog: logPath}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want the missing component reported", err)
	}

	dbPath := dir + "/missing/../db"
	if err := (&Config{Directory: dbPath}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "directory") {
		t.Fatalf("Validate() = %v, want the missing component reported", err)
	}
}

// TestValidateSymlinkTargetKeepsComponents pins the unix rule for a relative
// target. filepath.Join would clean "missing/../real.log" down to
// "real.log" — which looks like it lives somewhere that exists, while the
// open follows the target as written and fails on the missing component.
func TestValidateSymlinkTargetKeepsComponents(t *testing.T) {
	dir := t.TempDir()
	link := filepath.Join(dir, "access.log")
	if err := os.Symlink("missing/../real.log", link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := (&Config{AccessLog: link}).Validate(); err == nil ||
		!strings.Contains(err.Error(), "accesslog") {
		t.Fatalf("Validate() = %v, want the missing component in the target reported", err)
	}

	// The same shape with the component present is usable.
	if err := os.Mkdir(filepath.Join(dir, "there"), 0o750); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, "ok.log")
	if err := os.Symlink("there/../real.log", good); err != nil {
		t.Fatal(err)
	}
	if err := (&Config{AccessLog: good}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a target whose components all exist: %v", err)
	}
}

// TestValidateReadOnlyBlocklistDir pins that a blocklist directory is read,
// not necessarily written. The middleware loads local lists from it and only
// logs when it cannot download into it, so a read-only mount carrying nothing
// but local lists is a working setup. The working directory is different: the
// trust-anchor store lives there, so that one has to take an entry.
func TestValidateReadOnlyBlocklistDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes regardless of mode")
	}
	dir := t.TempDir()
	lists := filepath.Join(dir, "lists")
	if err := os.Mkdir(lists, 0o500); err != nil { //nolint:gosec // G301 - the point is a directory that cannot be written
		t.Fatal(err)
	}
	defer os.Chmod(lists, 0o700) //nolint:errcheck,gosec // test cleanup

	if err := (&Config{BlockListDir: lists}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a read-only blocklist directory: %v", err)
	}

	work := filepath.Join(dir, "work")
	if err := os.Mkdir(work, 0o500); err != nil { //nolint:gosec // G301 - the point is a directory that cannot be written
		t.Fatal(err)
	}
	defer os.Chmod(work, 0o700) //nolint:errcheck,gosec // test cleanup

	if err := (&Config{Directory: work}).Validate(); err == nil {
		t.Fatal("Validate() accepted a working directory it cannot write in")
	}
}

// TestValidateUnreadableBlocklistDir pins that a blocklist directory has to be
// listable. Stat says nothing about that — a directory with no permission bits
// satisfies it — while the middleware walks it and, when it cannot, logs once
// and loads no local list at all.
func TestValidateUnreadableBlocklistDir(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads regardless of mode")
	}
	dir := t.TempDir()
	lists := filepath.Join(dir, "lists")
	if err := os.Mkdir(lists, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(lists, 0o700) //nolint:errcheck,gosec // test cleanup

	if err := (&Config{BlockListDir: lists}).Validate(); err == nil {
		t.Fatal("Validate() accepted a blocklist directory it cannot list")
	}

	// Through a symlink too, since that is the path the middleware walks.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(lists, link); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if err := (&Config{BlockListDir: link}).Validate(); err == nil {
		t.Fatal("Validate() accepted a symlink to a directory it cannot list")
	}

	// Read-only is still fine: only writing is optional there.
	ro := filepath.Join(dir, "ro")
	if err := os.Mkdir(ro, 0o500); err != nil { //nolint:gosec // G301 - read-only is the point
		t.Fatal(err)
	}
	defer os.Chmod(ro, 0o700) //nolint:errcheck,gosec // test cleanup
	if err := (&Config{BlockListDir: ro}).Validate(); err != nil {
		t.Fatalf("Validate() rejected a read-only blocklist directory: %v", err)
	}
}
