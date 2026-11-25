//go:build !unix

package compactset

import (
	"errors"
	"os"
)

func openRollingArtifact(string) (*os.File, error) { return nil, errMmapUnsupported }

func mapFile(*os.File, int) ([]byte, error) { return nil, errMmapUnsupported }
func unmapFile([]byte) error                { return nil }

func rollingDevice(string) (uint64, error) { return 0, errors.ErrUnsupported }
