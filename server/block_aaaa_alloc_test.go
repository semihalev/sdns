//go:build !race

package server

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Like the existing server allocation pins, this excludes the race
// detector, which performs its own allocations.
func TestBlockAAAARawAllocatesNothing(t *testing.T) {
	for _, edns := range []bool{false, true} {
		for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
			t.Run(fmt.Sprintf("type=%d/edns=%v", qtype, edns), func(t *testing.T) {
				s := newBlockAAAAServer(t, nil)
				m := new(dns.Msg)
				m.SetQuestion("allocation.block-aaaa.test.", qtype)
				if edns {
					m.SetEdns0(1232, false)
				}
				raw, err := m.Pack()
				if err != nil {
					t.Fatal(err)
				}
				job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 54), Port: 4242}}
				for range 2 {
					if !s.ServeRaw(job, raw, time.Now()) {
						t.Fatal("warm serve not handled")
					}
				}
				runtime.GC()
				runtime.GC()
				// Fence the very first serve after GC as well as the warm
				// loop: storage belongs to the job, not a replenished pool.
				before := runtime.MemStats{}
				after := runtime.MemStats{}
				runtime.ReadMemStats(&before)
				if !s.ServeRaw(job, raw, time.Now()) {
					t.Fatal("post-GC serve not handled")
				}
				runtime.ReadMemStats(&after)
				if after.Mallocs != before.Mallocs {
					t.Fatalf("first post-GC serve allocated %d objects", after.Mallocs-before.Mallocs)
				}
				allocs := leastAllocsPerRun(100, func() {
					if !s.ServeRaw(job, raw, time.Now()) {
						t.Fatal("serve not handled")
					}
				})
				if allocs != 0 {
					t.Fatalf("allocs=%v, want 0", allocs)
				}
			})
		}
	}
}
