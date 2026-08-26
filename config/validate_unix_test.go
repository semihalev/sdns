//go:build unix

package config

import (
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
