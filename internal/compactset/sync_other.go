//go:build !linux

package compactset

import (
	"errors"
	"os"
	"path/filepath"
)

const rollingUsesSyncfs = false

func rollingSyncFiles(dir *os.File, names []string) error {
	for _, name := range names {
		f, err := os.OpenFile(filepath.Join(dir.Name(), name), os.O_RDWR, 0) //nolint:gosec // G304: names are the files staged by this store.
		if err != nil {
			return err
		}
		if err = errors.Join(f.Sync(), f.Close()); err != nil {
			return err
		}
	}
	return nil
}
