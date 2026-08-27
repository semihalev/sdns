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
