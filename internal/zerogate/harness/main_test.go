package main

import "testing"

// TestParkPrimitiveIsNarrow pins the one exemption the exact verdict
// makes.
//
// A sudog taken when a goroutine blocks is bookkeeping for blocking, not
// for the request, and it is bounded by the number of Ps rather than by
// traffic. Exempting it is defensible; exempting the packages it happens
// to live in is not — internal/poll and syscall are also where a buffer
// that genuinely escaped into a socket write would appear, and that is a
// regression wearing a platform frame.
func TestParkPrimitiveIsNarrow(t *testing.T) {
	for _, tc := range []struct {
		fn     string
		parked bool
	}{
		// The park machinery: what the profile showed when two workers
		// met on one socket's write lock.
		{"internal/poll.runtime_Semacquire", true},
		{"sync.runtime_SemacquireMutex", true},
		{"sync.runtime_Semrelease", true},
		{"sync.runtime_notifyListWait", true},

		// The same packages doing actual work. An allocation here is the
		// server's, however deep in the platform it happens.
		{"internal/poll.(*FD).WriteMsg", false},
		{"internal/poll.(*FD).ReadMsg", false},
		{"syscall.SendmsgN", false},
		{"syscall.anyToSockaddr", false},
		{"net.(*UDPConn).WriteMsgUDPAddrPort", false},
		{"github.com/semihalev/sdns/server.(*udpEngine).serve", false},
	} {
		if got := parkPrimitive(tc.fn); got != tc.parked {
			t.Errorf("parkPrimitive(%q) = %v, want %v", tc.fn, got, tc.parked)
		}
	}
}
