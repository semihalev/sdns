//go:build !windows

package resolver

import "os"

// syncDir fsyncs the given directory so a preceding rename's
// directory-entry update is durable, not just the file contents.
// Opens read-only because POSIX directory fsync only requires the
// inode handle, not write access.
func syncDir(path string) error {
	f, err := os.Open(path) //nolint:gosec // G304 - directory derived from caller-supplied filename
	if err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
