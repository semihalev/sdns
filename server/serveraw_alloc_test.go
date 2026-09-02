//go:build !race

package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// TestServeRawWireHitAllocatesNothing is the hard-zero contract itself,
// asserted where it can be exact: a warm exact-entry hit served through
// the raw ingress must not touch the allocator at all.
//
// The subprocess gate measures a whole process and can only bound what
// traffic adds over ambient noise; this runs the same path in-process,
// where AllocsPerRun sees every object. Both matter, the gate proves
// the shape survives real sockets and two GCs, this proves the number is
// zero rather than small.
//
// Excluded under the race detector, which allocates on its own.
func TestServeRawWireHitAllocatesNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		edns bool
	}{
		{name: "noopt"},
		{name: "edns", edns: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newHitChainServer(t)

			m := new(dns.Msg)
			m.SetQuestion("alloc.zero.test.", dns.TypeA)
			if tc.edns {
				m.SetEdns0(1232, true)
			}
			raw, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}

			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 40), Port: 4242}}
			// Warm: the first serve misses and admits, the second hits.
			for range 2 {
				job.wrote = job.wrote[:0]
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("warm serve not handled")
				}
			}
			if len(job.wrote) == 0 {
				t.Fatal("warm serve produced no reply")
			}
			if job.req.Raw() == nil {
				t.Fatal("the hit did not take the wire path")
			}

			if allocs := testing.AllocsPerRun(500, func() {
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("hit serve not handled")
				}
			}); allocs != 0 {
				t.Fatalf("a warm %s hit allocated %.2f objects per serve; the contract is none", tc.name, allocs)
			}
		})
	}
}
