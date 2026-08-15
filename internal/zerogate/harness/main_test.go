package main

import "testing"

// TestParkBookkeepingIsTheAllocatingFrame pins the one exemption the
// exact verdict makes.
//
// A sudog is what the scheduler records while a goroutine is parked. It
// is bookkeeping for blocking, bounded by how many goroutines can be
// parked at once rather than by traffic, so it is held to not scaling
// instead of to zero. What makes that exemption safe is naming the frame
// that allocates it: every park path in the runtime reaches
// acquireSudog, and nothing else does.
//
// The two rules this replaced were wrong in opposite directions, and both
// were caught by the gate on real traffic rather than by reasoning: a
// park on a channel shows *server* code as its first non-runtime frame,
// so classifying by the caller charged a real park to the server; and
// exempting the packages parks appear in — internal/poll, syscall —
// would have taken a buffer that genuinely escaped into a socket write
// out of the verdict along with them.
func TestParkBookkeepingIsTheAllocatingFrame(t *testing.T) {
	for _, tc := range []struct {
		name   string
		frames []string
		parked bool
	}{
		{
			name: "worker parked on the ready queue",
			frames: []string{
				"runtime.mallocgc", "runtime.newobject", sudogAlloc,
				"runtime.chanrecv", "runtime.chanrecv2",
				"github.com/semihalev/sdns/server.(*udpEngine).worker",
			},
			parked: true,
		},
		{
			name: "two writers meeting on a socket's write lock",
			frames: []string{
				"runtime.mallocgc", sudogAlloc, "runtime.semacquire1",
				"internal/poll.runtime_Semacquire", "internal/poll.(*fdMutex).rwlock",
				"internal/poll.(*FD).writeLock",
				"github.com/semihalev/sdns/server.(*udpEngine).sendGroup",
			},
			parked: true,
		},
		{
			name: "a buffer escaping into the socket write",
			frames: []string{
				"runtime.mallocgc", "runtime.makeslice",
				"internal/poll.(*FD).WriteMsg", "syscall.SendmsgN",
				"github.com/semihalev/sdns/server.(*udpJob).sendDirect",
			},
			parked: false,
		},
		{
			name: "the server allocating on its own",
			frames: []string{
				"runtime.mallocgc", "runtime.newobject",
				"github.com/semihalev/sdns/server.(*Server).ServeRaw",
				"github.com/semihalev/sdns/server.(*udpEngine).serve",
			},
			parked: false,
		},
	} {
		if got := parkBookkeeping(tc.frames); got != tc.parked {
			t.Errorf("%s: parkBookkeeping = %v, want %v", tc.name, got, tc.parked)
		}
	}
}
