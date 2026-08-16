//go:build !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package server

// fdSoftLimit is unknowable here; zero means "no descriptor bound".
func fdSoftLimit() uint64 { return 0 }
