//go:build unix

package config

import "syscall"

// nonBlockingOpen keeps a probe from waiting on the file it is asking about.
// A FIFO with no reader answers ENXIO instead of holding the open, which is
// the difference between reporting the problem and becoming it. On anything
// else it changes nothing.
const nonBlockingOpen = syscall.O_NONBLOCK
