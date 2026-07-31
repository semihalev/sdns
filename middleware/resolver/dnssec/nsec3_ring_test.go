package dnssec

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/miekg/dns"
)

func TestNSEC3RingHashWorkDoesNotScaleWithRecordCount(t *testing.T) {
	const qname = "exact.ring-work.example."

	for _, recordCount := range []int{2, 32} {
		t.Run(fmt.Sprintf("%d records", recordCount), func(t *testing.T) {
			ring := ringTestSetForExactName(t, qname, recordCount)
			work := &countingNSEC3Work{limit: 128}
			match, cover, err := newNSEC3RingEvaluator(ring, work).lookup(qname)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if match == nil || cover != nil {
				t.Fatalf("lookup = match:%t cover:%t, want exact match only",
					match != nil, cover != nil)
			}
			if work.calls != 1 {
				t.Fatalf("hash work = %d, want 1 for %d-record ring",
					work.calls, recordCount)
			}
		})
	}
}

func TestNSEC3RingRejectsExactMatchCoveredByAnotherInterval(t *testing.T) {
	const qname = "ambiguous.ring.example."
	parameters := ringTestParameters()
	target := ringTestHash(t, qname, parameters)
	coverOwner, coverNext := ringTestWrappingCover(t, target)

	ring := ringTestPreparedSet(t, []nsec3RingEntry{
		ringTestEntry(target, ringTestAdjacent(t, target)),
		ringTestEntry(coverOwner, coverNext),
	})
	match, cover, err := newNSEC3RingEvaluator(ring, nil).lookup(qname)
	if !errors.Is(err, ErrNSECMissingCoverage) {
		t.Fatalf("match-plus-cover lookup error = %v, want %v",
			err, ErrNSECMissingCoverage)
	}
	if match != nil || cover != nil {
		t.Fatalf("ambiguous lookup returned match:%t cover:%t, want neither",
			match != nil, cover != nil)
	}
}

func TestNSEC3RingWrapAndSingletonIntervals(t *testing.T) {
	const qname = "interval.ring.example."
	parameters := ringTestParameters()
	target := ringTestHash(t, qname, parameters)

	t.Run("wrap interval", func(t *testing.T) {
		owner, next := ringTestWrappingCover(t, target)
		if bytes.Compare(owner, next) <= 0 {
			t.Fatalf("test interval does not wrap: owner=%x next=%x", owner, next)
		}
		ring := ringTestPreparedSet(t, []nsec3RingEntry{
			ringTestEntry(owner, next),
		})
		match, cover, err := newNSEC3RingEvaluator(ring, nil).lookup(qname)
		if err != nil {
			t.Fatalf("wrap lookup: %v", err)
		}
		if match != nil || cover == nil {
			t.Fatalf("wrap lookup = match:%t cover:%t, want cover only",
				match != nil, cover != nil)
		}
	})

	t.Run("singleton covers every other hash", func(t *testing.T) {
		owner := ringTestAdjacent(t, target)
		ring := ringTestPreparedSet(t, []nsec3RingEntry{
			ringTestEntry(owner, owner),
		})
		match, cover, err := newNSEC3RingEvaluator(ring, nil).lookup(qname)
		if err != nil {
			t.Fatalf("singleton cover lookup: %v", err)
		}
		if match != nil || cover == nil {
			t.Fatalf("singleton cover lookup = match:%t cover:%t, want cover only",
				match != nil, cover != nil)
		}
	})

	t.Run("singleton owner is an exact match, not a cover", func(t *testing.T) {
		ring := ringTestPreparedSet(t, []nsec3RingEntry{
			ringTestEntry(target, target),
		})
		match, cover, err := newNSEC3RingEvaluator(ring, nil).lookup(qname)
		if err != nil {
			t.Fatalf("singleton exact lookup: %v", err)
		}
		if match == nil || cover != nil {
			t.Fatalf("singleton exact lookup = match:%t cover:%t, want match only",
				match != nil, cover != nil)
		}
	})
}

func TestPrepareNSEC3RingDeduplicatesIdenticalOwnerAndRejectsConflict(t *testing.T) {
	const (
		name = "duplicate.ring.example."
		zone = "example."
	)
	base := ringTestRecordForName(t, name, zone)
	base.TypeBitMap = []uint16{dns.TypeA, dns.TypeNS}

	duplicate := *base
	duplicate.Hdr.Ttl++
	duplicate.TypeBitMap = []uint16{dns.TypeNS, dns.TypeA}

	prepared, err := prepareNSEC3Set(
		[]dns.RR{base, &duplicate},
		zone,
	)
	if err != nil {
		t.Fatalf("semantic duplicate rejected: %v", err)
	}
	if len(prepared.entries) != 1 {
		t.Fatalf("semantic duplicate produced %d entries, want 1",
			len(prepared.entries))
	}

	conflict := *base
	conflict.TypeBitMap = []uint16{dns.TypeA, dns.TypeAAAA}
	if _, err := prepareNSEC3Set(
		[]dns.RR{base, &conflict},
		zone,
	); !errors.Is(err, ErrNSECMissingCoverage) {
		t.Fatalf("conflicting owner error = %v, want %v",
			err, ErrNSECMissingCoverage)
	}
}

func TestPrepareNSEC3RingRejectsMixedParameterChainsBeforeHashWork(t *testing.T) {
	const (
		qname = "missing.rollover.example."
		zone  = "example."
	)
	primary := ringTestNSEC3SingletonChain(t, zone, 0, "", 0)

	tests := []struct {
		name           string
		second         []dns.RR
		secondComplete bool
	}{
		{
			name: "second complete chain",
			second: []dns.RR{
				ringTestNSEC3SingletonChain(t, zone, 0, "AA", 1),
			},
			secondComplete: true,
		},
		{
			name: "second incomplete chain",
			second: []dns.RR{
				ringTestNSEC3PartialChain(t, qname, zone, 0, "AA", 1),
			},
		},
	}

	verify := func(records []dns.RR, work NSEC3Work) error {
		t.Helper()
		msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
		msg.Rcode = dns.RcodeNameError
		_, err := VerifyNameErrorForZoneWithWork(msg, records, zone, work)
		return err
	}

	if err := verify([]dns.RR{primary}, nil); err != nil {
		t.Fatalf("primary complete chain rejected: %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.secondComplete {
				if err := verify(tt.second, nil); err != nil {
					t.Fatalf("second complete chain rejected in isolation: %v", err)
				}
			} else if err := verify(tt.second, nil); !errors.Is(err, ErrNSECMissingCoverage) {
				t.Fatalf("second incomplete chain error = %v, want %v",
					err, ErrNSECMissingCoverage)
			}

			records := append([]dns.RR{primary}, tt.second...)
			work := &countingNSEC3Work{limit: 128}
			if err := verify(records, work); !errors.Is(err, ErrNSECMissingCoverage) {
				t.Fatalf("mixed-parameter response error = %v, want %v",
					err, ErrNSECMissingCoverage)
			}
			if work.calls != 0 {
				t.Fatalf("mixed-parameter preflight consumed %d hash debits, want 0",
					work.calls)
			}
		})
	}
}

func TestNSEC3RingLookupMatchesStrictIntervalReference(t *testing.T) {
	const cases = 256
	parameters := ringTestParameters()
	generator := ringTestGenerator(0x7f4a7c159e3779b9)

	for caseIndex := 0; caseIndex < cases; caseIndex++ {
		qname := fmt.Sprintf("q-%03d.property.example.", caseIndex)
		target := ringTestHash(t, qname, parameters)
		entryCount := 1 + int(generator.next()%12)
		entries := make([]nsec3RingEntry, 0, entryCount)
		owners := make(map[string]struct{}, entryCount)

		for len(entries) < entryCount {
			owner := generator.hash()
			if caseIndex%7 == 0 && len(entries) == 0 {
				owner = bytes.Clone(target)
			}
			if _, duplicate := owners[string(owner)]; duplicate {
				continue
			}
			owners[string(owner)] = struct{}{}
			entries = append(entries, ringTestEntry(owner, generator.hash()))
		}

		ring := ringTestPreparedSet(t, entries)
		var wantMatch, wantCover *nsec3RingEntry
		ambiguous := false
		for i := range ring.entries {
			entry := &ring.entries[i]
			if bytes.Equal(entry.ownerHash, target) {
				if wantMatch != nil {
					ambiguous = true
				}
				wantMatch = entry
				continue
			}
			if !ringTestStrictlyCovers(
				entry.ownerHash,
				entry.nextHash,
				target,
			) {
				continue
			}
			if wantCover != nil {
				ambiguous = true
			}
			wantCover = entry
		}
		if wantMatch != nil && wantCover != nil {
			ambiguous = true
		}

		gotMatch, gotCover, err := newNSEC3RingEvaluator(ring, nil).lookup(qname)
		if ambiguous {
			if !errors.Is(err, ErrNSECMissingCoverage) {
				t.Fatalf("case %d ambiguous lookup error = %v, want %v",
					caseIndex, err, ErrNSECMissingCoverage)
			}
			if gotMatch != nil || gotCover != nil {
				t.Fatalf("case %d ambiguous lookup returned match:%t cover:%t",
					caseIndex, gotMatch != nil, gotCover != nil)
			}
			continue
		}
		if err != nil {
			t.Fatalf("case %d lookup: %v", caseIndex, err)
		}
		if gotMatch != wantMatch || gotCover != wantCover {
			t.Fatalf(
				"case %d lookup = match:%s cover:%s, want match:%s cover:%s",
				caseIndex,
				ringTestEntryOwner(gotMatch),
				ringTestEntryOwner(gotCover),
				ringTestEntryOwner(wantMatch),
				ringTestEntryOwner(wantCover),
			)
		}
	}
}

func ringTestSetForExactName(
	t *testing.T,
	name string,
	recordCount int,
) preparedNSEC3Set {
	t.Helper()
	parameters := ringTestParameters()
	target := ringTestHash(t, name, parameters)
	entries := []nsec3RingEntry{
		ringTestEntry(target, ringTestAdjacent(t, target)),
	}
	generator := ringTestGenerator(0xa0761d6478bd642f)
	owners := map[string]struct{}{string(target): {}}
	for len(entries) < recordCount {
		owner := generator.hash()
		if _, duplicate := owners[string(owner)]; duplicate {
			continue
		}
		next := ringTestIncrement(owner)
		if next == nil ||
			ringTestStrictlyCovers(owner, next, target) {
			continue
		}
		owners[string(owner)] = struct{}{}
		entries = append(entries, ringTestEntry(owner, next))
	}
	return ringTestPreparedSet(t, entries)
}

func ringTestPreparedSet(
	t *testing.T,
	entries []nsec3RingEntry,
) preparedNSEC3Set {
	t.Helper()
	zone, err := newAggressiveCanonicalName("example.")
	if err != nil {
		t.Fatalf("canonical zone: %v", err)
	}
	sort.Slice(entries, func(i, j int) bool {
		return bytes.Compare(entries[i].ownerHash, entries[j].ownerHash) < 0
	})
	return preparedNSEC3Set{
		zone:       zone,
		qclass:     dns.ClassINET,
		parameters: ringTestParameters(),
		entries:    entries,
	}
}

func ringTestParameters() aggressiveNSEC3Parameters {
	return aggressiveNSEC3Parameters{
		hash: dns.SHA1,
	}
}

func ringTestHash(
	t *testing.T,
	name string,
	parameters aggressiveNSEC3Parameters,
) []byte {
	t.Helper()
	canonical, err := newAggressiveCanonicalName(name)
	if err != nil {
		t.Fatalf("canonical name %q: %v", name, err)
	}
	return calculateAggressiveNSEC3Hash(canonical, parameters)
}

func ringTestEntry(owner, next []byte) nsec3RingEntry {
	owner = bytes.Clone(owner)
	next = bytes.Clone(next)
	return nsec3RingEntry{
		rr: &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   aggressiveNSEC3Base32.EncodeToString(owner) + ".example.",
				Class:  dns.ClassINET,
				Rrtype: dns.TypeNSEC3,
			},
			Hash:       dns.SHA1,
			HashLength: 20,
			NextDomain: aggressiveNSEC3Base32.EncodeToString(next),
		},
		ownerHash: owner,
		nextHash:  next,
	}
}

func ringTestRecordForName(
	t *testing.T,
	name string,
	zone string,
) *dns.NSEC3 {
	t.Helper()
	parameters := ringTestParameters()
	owner := ringTestHash(t, name, parameters)
	next := ringTestAdjacent(t, owner)
	record := ringTestEntry(owner, next).rr
	record.Hdr.Name = aggressiveNSEC3Base32.EncodeToString(owner) + "." + dns.Fqdn(zone)
	return record
}

func ringTestNSEC3SingletonChain(
	t *testing.T,
	zone string,
	iterations uint16,
	salt string,
	saltLength uint8,
) *dns.NSEC3 {
	t.Helper()
	apexHash := aggressiveTestNSEC3Hash(t, zone, iterations, salt)
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   aggressiveTestNSEC3Owner(apexHash, zone),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: iterations,
		SaltLength: saltLength,
		Salt:       salt,
		HashLength: 20,
		NextDomain: apexHash,
		TypeBitMap: []uint16{dns.TypeNS, dns.TypeSOA},
	}
}

func ringTestNSEC3PartialChain(
	t *testing.T,
	name string,
	zone string,
	iterations uint16,
	salt string,
	saltLength uint8,
) *dns.NSEC3 {
	t.Helper()
	hash := aggressiveTestNSEC3Hash(t, name, iterations, salt)
	return &dns.NSEC3{
		Hdr: dns.RR_Header{
			Name: aggressiveTestNSEC3Owner(
				adjacentNSEC3Hash(t, hash, -1),
				zone,
			),
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    300,
		},
		Hash:       dns.SHA1,
		Iterations: iterations,
		SaltLength: saltLength,
		Salt:       salt,
		HashLength: 20,
		NextDomain: adjacentNSEC3Hash(t, hash, 1),
	}
}

func ringTestWrappingCover(
	t *testing.T,
	target []byte,
) (owner, next []byte) {
	t.Helper()
	higher1 := ringTestIncrement(target)
	if higher1 != nil {
		higher2 := ringTestIncrement(higher1)
		if higher2 != nil {
			return higher2, higher1
		}
	}
	lower1 := ringTestDecrement(target)
	if lower1 != nil {
		lower2 := ringTestDecrement(lower1)
		if lower2 != nil {
			return lower1, lower2
		}
	}
	t.Fatalf("cannot construct wrap interval around %x", target)
	return nil, nil
}

func ringTestAdjacent(t *testing.T, value []byte) []byte {
	t.Helper()
	if next := ringTestIncrement(value); next != nil {
		return next
	}
	if previous := ringTestDecrement(value); previous != nil {
		return previous
	}
	t.Fatalf("cannot find adjacent hash for %x", value)
	return nil
}

func ringTestIncrement(value []byte) []byte {
	result := bytes.Clone(value)
	for i := len(result) - 1; i >= 0; i-- {
		if result[i] != 0xff {
			result[i]++
			return result
		}
		result[i] = 0
	}
	return nil
}

func ringTestDecrement(value []byte) []byte {
	result := bytes.Clone(value)
	for i := len(result) - 1; i >= 0; i-- {
		if result[i] != 0 {
			result[i]--
			return result
		}
		result[i] = 0xff
	}
	return nil
}

// ringTestStrictlyCovers is deliberately independent of the implementation
// helper. It is the RFC 5155 ring predicate: owner and next are excluded,
// ordinary intervals do not wrap, owner > next intervals wrap through zero,
// and owner == next represents the full ring except the existing owner.
func ringTestStrictlyCovers(owner, next, value []byte) bool {
	switch bytes.Compare(owner, next) {
	case 0:
		return !bytes.Equal(value, owner)
	case -1:
		return bytes.Compare(owner, value) < 0 &&
			bytes.Compare(value, next) < 0
	default:
		return bytes.Compare(owner, value) < 0 ||
			bytes.Compare(value, next) < 0
	}
}

type ringTestGenerator uint64

func (g *ringTestGenerator) next() uint64 {
	*g = *g*6364136223846793005 + 1442695040888963407
	return uint64(*g)
}

func (g *ringTestGenerator) hash() []byte {
	result := make([]byte, 20)
	for offset := 0; offset < len(result); offset += 8 {
		var encoded [8]byte
		binary.LittleEndian.PutUint64(encoded[:], g.next())
		copy(result[offset:], encoded[:])
	}
	return result
}

func ringTestEntryOwner(entry *nsec3RingEntry) string {
	if entry == nil {
		return "<nil>"
	}
	return fmt.Sprintf("%x", entry.ownerHash)
}
