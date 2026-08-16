//go:build !linux && !darwin

package server

// systemMemoryBytes cannot be answered portably. Zero means "the budget
// is unknown", which the caller reads as the conservative default rather
// than as "no memory".
func systemMemoryBytes() uint64 { return 0 }

// containerMemoryLimit is a cgroup concept.
func containerMemoryLimit() uint64 { return 0 }
