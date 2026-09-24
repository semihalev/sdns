package atomicfile

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func writeString(s string) func(io.Writer) error {
	return func(w io.Writer) error {
		_, err := io.WriteString(w, s)
		return err
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func leftovers(t *testing.T, dir string) []string {
	t.Helper()
	names, err := filepath.Glob(filepath.Join(dir, "*.tmp.*"))
	if err != nil {
		t.Fatal(err)
	}
	return names
}

func TestWriteReplacesTheFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copy")
	if err := Write(path, writeString("first")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, writeString("second")); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, path); got != "second" {
		t.Fatalf("contents = %q, want %q", got, "second")
	}
	if names := leftovers(t, filepath.Dir(path)); len(names) != 0 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}

// A writer that fails part way leaves the previous file whole.
func TestWriteFailureKeepsThePreviousFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "copy")
	if err := Write(path, writeString("kept")); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	err := Write(path, func(w io.Writer) error {
		_, _ = io.WriteString(w, "half")
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want the writer's error", err)
	}
	if got := readFile(t, path); got != "kept" {
		t.Fatalf("contents = %q, want the previous file", got)
	}
	if names := leftovers(t, filepath.Dir(path)); len(names) != 0 {
		t.Fatalf("temporary files left behind: %v", names)
	}
}

// A temporary file an interrupted write left behind is cleared by the next
// write of the same path, and only of that path.
func TestWriteClearsItsOwnLeftovers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "copy")
	stale := filepath.Join(dir, "copy.tmp.123")
	other := filepath.Join(dir, "other.tmp.123")
	for _, name := range []string{stale, other} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := Write(path, writeString("new")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("leftover of this path survived: %v", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("another path's temporary file was removed: %v", err)
	}
}
