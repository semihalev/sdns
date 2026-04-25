//go:build windows

package resolver

// syncDir is a no-op on Windows. The Win32 API doesn't expose a
// directly callable "fsync this directory" — FlushFileBuffers on a
// directory handle requires GENERIC_WRITE access, which os.Open
// doesn't grant, and there is no widely-supported equivalent.
// NTFS journals filesystem metadata, so a successful rename is
// durable to the same extent the file contents are.
func syncDir(path string) error {
	return nil
}
