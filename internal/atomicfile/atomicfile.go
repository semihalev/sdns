// Package atomicfile replaces files so that a reader, or a process starting
// after a crash, finds either the previous contents or the new ones, never a
// mix of the two.
package atomicfile

import (
	"bufio"
	"io"
	"os"
	"path/filepath"
)

// Write replaces path with what write produces. The bytes go to a temporary
// file in the same directory, which is synced and renamed over path, and the
// directory is then synced so the rename itself survives a crash.
//
// An error before the rename leaves path as it was. An error from the final
// directory sync is returned as well, but path already holds the new contents
// by then; what is uncertain is only whether the rename survives a crash.
//
// Write assumes it is the only writer of path. It removes temporary files an
// earlier, interrupted Write left beside path, which would race a concurrent
// writer's.
func Write(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	pattern := filepath.Base(path) + ".tmp.*"
	if stale, err := filepath.Glob(filepath.Join(dir, pattern)); err == nil {
		for _, name := range stale {
			_ = os.Remove(name)
		}
	}

	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	fail := func(err error) error {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}

	w := bufio.NewWriter(f)
	if err := write(w); err != nil {
		return fail(err)
	}
	if err := w.Flush(); err != nil {
		return fail(err)
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return SyncDir(dir)
}
