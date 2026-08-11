package dnssec

import (
	"strings"
	"testing"

	"github.com/miekg/dns"
)

func nsecRecord(owner, next string, types ...uint16) *dns.NSEC {
	return &dns.NSEC{
		Hdr: dns.RR_Header{
			Name:   owner,
			Rrtype: dns.TypeNSEC,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		NextDomain: next,
		TypeBitMap: types,
	}
}

func nsecRecordClass(owner, next string, class uint16, types ...uint16) *dns.NSEC {
	rr := nsecRecord(owner, next, types...)
	rr.Hdr.Class = class
	return rr
}

// TestEvaluateAggressiveNSECPreparedMatchesRecords is the contract that lets
// the denial-proof cache canonicalize once at admission instead of on every
// lookup: evaluating pre-canonicalized records must reach exactly the same
// verdict as evaluating the records themselves — same rcode, same proof
// records, and the same refusal for the same reason.
//
// The cases deliberately include the set-level rejections, since those are
// the checks that stayed behind in the evaluator when canonicalization
// moved out of it.
func TestEvaluateAggressiveNSECPreparedMatchesRecords(t *testing.T) {
	const zone = "example.com."

	cases := []struct {
		name    string
		q       dns.Question
		records []dns.RR
	}{
		{
			name: "nxdomain between two owners",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
				nsecRecord("example.com.", "a.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
			},
		},
		{
			name: "nodata at an existing owner",
			q:    dns.Question{Name: "a.example.com.", Qtype: dns.TypeAAAA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
			},
		},
		{
			name: "duplicate records collapse",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
				nsecRecord("example.com.", "a.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
			},
		},
		{
			name: "mixed case owner is folded",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("A.ExAmPlE.CoM.", "C.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
				nsecRecord("example.com.", "a.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
			},
		},
		{
			name: "conflicting owners are refused",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeA),
				nsecRecord("a.example.com.", "d.example.com.", dns.TypeA),
			},
		},
		{
			name: "record crossing the signer zone is refused",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.org.", "c.example.org.", dns.TypeA),
			},
		},
		{
			name: "non-apex singleton interval is refused",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "a.example.com.", dns.TypeA),
			},
		},
		{
			name: "foreign class is refused",
			q:    dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecordClass("a.example.com.", "c.example.com.", dns.ClassCHAOS, dns.TypeA),
			},
		},
		{
			name:    "empty set is refused",
			q:       dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: nil,
		},
		{
			name: "delegation bitmap is refused",
			q:    dns.Question{Name: "sub.a.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
			records: []dns.RR{
				nsecRecord("a.example.com.", "c.example.com.", dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantResult, wantErr := EvaluateAggressiveNSEC(tc.q, zone, tc.records)

			prepared := make([]PreparedNSEC, 0, len(tc.records))
			for _, rr := range tc.records {
				nsec, ok := rr.(*dns.NSEC)
				if !ok {
					t.Fatalf("fixture holds a %T", rr)
				}
				// A record the preparer rejects could never be evaluated
				// either; the cases here are all preparable.
				p, err := PrepareAggressiveNSEC(nsec)
				if err != nil {
					t.Fatalf("PrepareAggressiveNSEC(%v): %v", nsec.Header().Name, err)
				}
				prepared = append(prepared, p)
			}

			gotResult, gotErr := EvaluateAggressiveNSECPrepared(tc.q, zone, prepared)

			switch {
			case wantErr == nil && gotErr != nil:
				t.Fatalf("records path succeeded but prepared path failed: %v", gotErr)
			case wantErr != nil && gotErr == nil:
				t.Fatalf("records path failed (%v) but prepared path succeeded", wantErr)
			case wantErr != nil && gotErr != nil:
				if wantErr.Error() != gotErr.Error() {
					t.Fatalf("refusal differs:\n  records:  %v\n  prepared: %v", wantErr, gotErr)
				}
				return
			}

			if gotResult.Rcode != wantResult.Rcode {
				t.Fatalf("rcode %d, want %d", gotResult.Rcode, wantResult.Rcode)
			}
			if len(gotResult.Proof) != len(wantResult.Proof) {
				t.Fatalf("proof has %d records, want %d",
					len(gotResult.Proof), len(wantResult.Proof))
			}
			for i := range wantResult.Proof {
				// Identity, not equality: callers match the returned proof
				// back to the records they supplied.
				if gotResult.Proof[i] != wantResult.Proof[i] {
					t.Fatalf("proof[%d] is %v, want the same record instance %v",
						i, gotResult.Proof[i], wantResult.Proof[i])
				}
			}
		})
	}
}

// TestPrepareAggressiveNSECRejectsNonNSEC pins that preparation refuses what
// it cannot canonicalize, so a caller storing prepared records never holds a
// half-built entry.
func TestPrepareAggressiveNSECRejectsNonNSEC(t *testing.T) {
	if _, err := PrepareAggressiveNSEC(nil); err == nil {
		t.Fatal("a nil record must be refused")
	}

	wrongType := nsecRecord("a.example.com.", "c.example.com.", dns.TypeA)
	wrongType.Hdr.Rrtype = dns.TypeA
	if _, err := PrepareAggressiveNSEC(wrongType); err == nil {
		t.Fatal("a record that is not an NSEC must be refused")
	}

	// A label may hold spaces, so an "obviously bad" name still packs;
	// exceeding the 63-octet label limit is what the packer rejects.
	bad := nsecRecord("a.example.com.", strings.Repeat("x", 64)+".example.com.", dns.TypeA)
	if _, err := PrepareAggressiveNSEC(bad); err == nil {
		t.Fatal("an unpackable next-domain name must be refused")
	}
}

// TestPrepareAggressiveNSECSizesItsBuffers pins what makes the prepared
// form safe to retain. Canonicalization packs into a 255-octet scratch
// buffer and keeps a view of it, which is free for a name used and dropped
// inside one evaluation — but a cache entry holds its names for as long as
// the record lives, and the cache's byte budget does not see them. Sized
// down, an entry retains its names rather than two 255-octet buffers.
func TestPrepareAggressiveNSECSizesItsBuffers(t *testing.T) {
	prepared, err := PrepareAggressiveNSEC(
		nsecRecord("a.example.com.", "c.example.com.", dns.TypeA))
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	for _, held := range []struct {
		what string
		name aggressiveCanonicalName
	}{
		{"owner", prepared.entry.owner},
		{"next", prepared.entry.next},
	} {
		if cap(held.name.wire) != len(held.name.wire) {
			t.Errorf("%s retains a %d-octet buffer for a %d-octet name",
				held.what, cap(held.name.wire), len(held.name.wire))
		}
		if cap(held.name.labels) != len(held.name.labels) {
			t.Errorf("%s retains room for %d labels but has %d",
				held.what, cap(held.name.labels), len(held.name.labels))
		}
	}

	// Sizing down must not disturb what the name means: the wire form backs
	// equality, and the label views back the zone and ordering comparisons.
	direct, err := newAggressiveCanonicalName("a.example.com.")
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	zone, err := newAggressiveCanonicalName("example.com.")
	if err != nil {
		t.Fatalf("canonicalize zone: %v", err)
	}
	if !prepared.entry.owner.equal(direct) {
		t.Fatal("compacted owner is not equal to the same name canonicalized directly")
	}
	if !prepared.entry.owner.isSubdomainOf(zone) {
		t.Fatal("compacted owner lost its label views")
	}
	if prepared.entry.owner.compare(direct) != 0 {
		t.Fatal("compacted owner orders differently from the same name")
	}
}

// TestPrepareAggressiveNSECIsAllocatedOnce pins the point of the whole
// exercise: evaluating prepared records must not re-canonicalize, which
// shows up as a materially smaller allocation count per evaluation.
func TestPrepareAggressiveNSECIsAllocatedOnce(t *testing.T) {
	const zone = "example.com."
	q := dns.Question{Name: "b.example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	records := []dns.RR{
		nsecRecord("a.example.com.", "c.example.com.", dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC),
		nsecRecord("example.com.", "a.example.com.", dns.TypeSOA, dns.TypeNS, dns.TypeRRSIG, dns.TypeNSEC),
	}

	prepared := make([]PreparedNSEC, 0, len(records))
	for _, rr := range records {
		p, err := PrepareAggressiveNSEC(rr.(*dns.NSEC))
		if err != nil {
			t.Fatalf("prepare: %v", err)
		}
		prepared = append(prepared, p)
	}

	fromRecords := testing.AllocsPerRun(100, func() {
		if _, err := EvaluateAggressiveNSEC(q, zone, records); err != nil {
			t.Fatalf("records path: %v", err)
		}
	})
	fromPrepared := testing.AllocsPerRun(100, func() {
		if _, err := EvaluateAggressiveNSECPrepared(q, zone, prepared); err != nil {
			t.Fatalf("prepared path: %v", err)
		}
	})

	if fromPrepared >= fromRecords {
		t.Fatalf("prepared evaluation allocated %.0f times, records path %.0f; "+
			"the canonicalization is not actually being reused",
			fromPrepared, fromRecords)
	}
	t.Logf("allocations per evaluation: records=%.0f prepared=%.0f", fromRecords, fromPrepared)
}
