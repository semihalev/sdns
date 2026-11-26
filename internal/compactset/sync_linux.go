package compactset

import (
	"os"

	"golang.org/x/sys/unix"
)

const rollingUsesSyncfs = true

func rollingSyncFiles(dir *os.File, _ []string) error {
	return unix.Syncfs(int(dir.Fd()))
}
