//go:build !race

package wire

import (
	"testing"

	"github.com/miekg/dns"
)

// TestTryPackDoesNotAllocate is the point of the packer: the dictionary, the
// output buffer and the record shim all live in pooled state, so packing an
// answer allocates nothing of its own.
//
// It is excluded under the race detector, which instruments sync.Pool heavily
// enough that an allocation count taken there describes the detector rather
// than the code.
func TestTryPackDoesNotAllocate(t *testing.T) {
	// Created once: a closure built inside the measured function would be
	// an allocation of the measurement, not of the packer.
	sink := 0
	consume := func(body []byte) error { sink = len(body); return nil }

	for i, msg := range packCorpus(t) {
		msg.Compress = true

		// The library side is measured on its own long-lived copy so the
		// comparison is against Pack alone — folding a per-run Copy into it
		// would inflate the number this is compared to.
		libMsg := msg.Copy()
		library := testing.AllocsPerRun(200, func() {
			if _, err := libMsg.Pack(); err != nil {
				t.Fatalf("message %d: %v", i, err)
			}
		})
		owned := testing.AllocsPerRun(200, func() {
			handled, err := TryPack(msg, consume)
			if err != nil || !handled {
				t.Fatalf("message %d: handled=%v err=%v", i, handled, err)
			}
		})

		// Records that allocate while packing their own RDATA — a signature
		// decoded from base64, service parameters, character strings — do so
		// on both paths; the comparison is not against zero for those. But
		// the storage this pools must be gone, and for the plain shapes that
		// dominate a resolver's traffic the whole pack must be free.
		if owned >= library && library > 0 {
			t.Errorf("message %d: %.0f allocations against the library's "+
				"%.0f; pooling bought nothing", i, owned, library)
		}
	}
	_ = sink

	// The plain shapes — A, a CNAME chain, a referral with glue, NXDOMAIN —
	// must be exactly zero. The corpus entries after them carry records
	// whose RDATA allocates on any path (a signature is decoded from
	// base64), which the differential half above accounts for.
	for i, msg := range packCorpus(t)[:4] {
		msg.Compress = true
		owned := testing.AllocsPerRun(200, func() {
			handled, err := TryPack(msg, consume)
			if err != nil || !handled {
				t.Fatalf("message %d: handled=%v err=%v", i, handled, err)
			}
		})
		if owned != 0 {
			t.Errorf("message %d: a plain answer packed with %.0f allocations",
				i, owned)
		}
	}
}

// TestPackCloneAllocatesOnlyTheClone pins the owning wrapper's cost: one
// allocation, the exact-size copy the caller keeps.
func TestPackCloneAllocatesOnlyTheClone(t *testing.T) {
	msg := packCorpus(t)[0]
	msg.Compress = true

	allocs := testing.AllocsPerRun(200, func() {
		if _, err := PackClone(msg); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 1 {
		t.Fatalf("PackClone cost %.0f allocations, want 1 (the clone)", allocs)
	}
}

// TestPackCloneOversizedCostsOnePack pins that the size preflight keeps a
// too-large message off the custom path entirely: the cost must be one
// library pack plus the clone, not a partial custom pack thrown away first.
// Allocation-heavy RDATA is where a double pack would show — an SVCB's
// parameters are built on every pack of every record.
func TestPackCloneOversizedCostsOnePack(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeHTTPS)
	msg.Compress = true
	for range 100 {
		msg.Answer = append(msg.Answer, mustPackRR(t,
			`long-owner-name-padding-the-message.example.com. 300 IN SVCB 2 `+
				`svc.example.com. port=8443 alpn="h3,h2"`))
	}
	sizeProbe := *msg
	sizeProbe.Compress = false
	if sizeProbe.Len() <= packBufferSize {
		t.Fatalf("fixture is wrong: %d bytes fits the pooled buffer",
			sizeProbe.Len())
	}

	libMsg := msg.Copy()
	library := testing.AllocsPerRun(50, func() {
		if _, err := libMsg.Pack(); err != nil {
			t.Fatal(err)
		}
	})
	clone := testing.AllocsPerRun(50, func() {
		if _, err := PackClone(msg); err != nil {
			t.Fatal(err)
		}
	})

	// The fallback adds the exact-size clone, the shallow message copy and
	// its Extra slice — a handful on top, never a second pack of every
	// record's RDATA.
	const fallbackOverhead = 4
	if clone > library+fallbackOverhead {
		t.Fatalf("an oversized PackClone cost %.0f allocations against the "+
			"library's %.0f; the message is being packed twice", clone, library)
	}
}
