//go:build !race

package server

import (
	"fmt"
	"net"
	"runtime"
	"sync"
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
				if allocs := leastAllocsAfterGC(func() {
					if !s.ServeRaw(job, raw, time.Now()) {
						t.Fatal("serve not handled")
					}
				}); allocs != 0 {
					t.Fatalf("first post-GC serve allocated %d objects", allocs)
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

// leastAllocsAfterGC repeats one cold call after two collections and keeps
// the minimum to filter unrelated process-wide background allocations.
func leastAllocsAfterGC(fn func()) uint64 {
	var least uint64
	for trial := range 3 {
		runtime.GC()
		runtime.GC()
		before := runtime.MemStats{}
		after := runtime.MemStats{}
		runtime.ReadMemStats(&before)
		fn()
		runtime.ReadMemStats(&after)
		allocs := after.Mallocs - before.Mallocs
		if trial == 0 || allocs < least {
			least = allocs
		}
		if least == 0 {
			break
		}
	}
	return least
}

type allocationControlObject [64]byte

var allocationControlSink *allocationControlObject

func TestLeastAllocsAfterGCDetectsColdPoolAllocation(t *testing.T) {
	pool := sync.Pool{New: func() any { return &allocationControlObject{} }}
	pool.Put(&allocationControlObject{})
	callback := func() {
		allocationControlSink = pool.Get().(*allocationControlObject)
		pool.Put(allocationControlSink)
	}
	if allocs := testing.AllocsPerRun(100, callback); allocs != 0 {
		t.Fatalf("warm pool callback allocated %v objects, want 0", allocs)
	}
	if allocs := leastAllocsAfterGC(callback); allocs == 0 {
		t.Fatal("cold pool callback allocated no objects, want at least one")
	}
}
