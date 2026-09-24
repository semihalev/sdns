//go:build !windows

package cache

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/atomicfile"
)

// TestSnapshotMeasure is the save and restore measurement, not a unit test.
// It runs only when SDNS_SNAPSHOT_MEASURE names a phase, and the two phases
// are separate processes so the restoring one never holds the cache it was
// saved from:
//
//	SDNS_SNAPSHOT_MEASURE=save SDNS_SNAPSHOT_DIR=/tmp/snap go test ./middleware/cache -run TestSnapshotMeasure -v -count=1
//	SDNS_SNAPSHOT_MEASURE=load SDNS_SNAPSHOT_DIR=/tmp/snap go test ./middleware/cache -run TestSnapshotMeasure -v -count=1
//
// SDNS_SNAPSHOT_N sets the answer count (default 1,000,000), half of them
// DNSSEC signed; SDNS_SNAPSHOT_RAW=1 writes without compression.
func TestSnapshotMeasure(t *testing.T) {
	phase := os.Getenv("SDNS_SNAPSHOT_MEASURE")
	if phase == "" {
		t.Skip("measurement; set SDNS_SNAPSHOT_MEASURE=save or load")
	}
	dir := os.Getenv("SDNS_SNAPSHOT_DIR")
	if dir == "" {
		t.Fatal("SDNS_SNAPSHOT_DIR is required")
	}
	n := 1_000_000
	if v, err := strconv.Atoi(os.Getenv("SDNS_SNAPSHOT_N")); err == nil && v > 0 {
		n = v
	}
	path := filepath.Join(dir, snapshotFile)
	s := newSnapshotStore(t, n, 24*time.Hour)

	switch phase {
	case "save":
		cpu0, t0 := cpuTime(), time.Now()
		for i := range n {
			s.SetFromResponse(measureAnswer(i), false, time.Time{})
		}
		warm, warmCPU := time.Since(t0), cpuTime()-cpu0
		heap, rss := memory()
		t.Logf("warm by admission: %d answers held in %v (cpu %v), heap %s, peak rss %s",
			s.PositiveLen(), warm.Round(time.Millisecond), warmCPU.Round(time.Millisecond), mb(heap), mb(rss))

		compression := uint16(snapshotLZ4)
		if os.Getenv("SDNS_SNAPSHOT_RAW") == "1" {
			compression = snapshotRaw
		}
		var saved snapshotSaved
		cpu0, t0 = cpuTime(), time.Now()
		err := atomicfile.Write(path, func(w io.Writer) error {
			var err error
			saved, err = s.snapshot(w, testFingerprint, compression, time.Now(), func(int) bool { return false })
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(path) //nolint:gosec // operator-named measurement path
		if err != nil {
			t.Fatal(err)
		}
		size := uint64(st.Size()) //nolint:gosec // a file size is non-negative
		t.Logf("save (walk, encode, fsync, rename): %d answers in %v (cpu %v), file %s, compression %d",
			saved.saved, time.Since(t0).Round(time.Millisecond), (cpuTime() - cpu0).Round(time.Millisecond), mb(size), compression)
		runtime.KeepAlive(s)

	case "load":
		f, err := os.Open(path) //nolint:gosec // operator-named measurement path
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close() //nolint:errcheck // read-only

		cpu0, t0 := cpuTime(), time.Now()
		if _, err := scanSnapshot(f, never, nil); err != nil {
			t.Fatal(err)
		}
		verify, verifyCPU := time.Since(t0), cpuTime()-cpu0
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}

		cpu0, t0 = cpuTime(), time.Now()
		got, err := s.restore(f, testFingerprint, never, time.Now)
		if err != nil {
			t.Fatal(err)
		}
		total, totalCPU := time.Since(t0), cpuTime()-cpu0
		heap, rss := memory()
		t.Logf("restore (both passes): %d loaded, %d expired, %d refused, %d held, in %v (cpu %v); verify pass alone %v (cpu %v); heap %s, peak rss %s",
			got.loaded, got.expired, got.refused, s.PositiveLen(), total.Round(time.Millisecond), totalCPU.Round(time.Millisecond),
			verify.Round(time.Millisecond), verifyCPU.Round(time.Millisecond), mb(heap), mb(rss))
		if got.loaded != n {
			t.Errorf("loaded %d of %d", got.loaded, n)
		}
		runtime.KeepAlive(s)

	default:
		t.Fatalf("unknown phase %q", phase)
	}
}

// measureAnswer is the i-th answer of a cache shaped like a validating
// resolver's: half signed positive answers, a third unsigned, and the rest
// signed denials with their proofs.
func measureAnswer(i int) *dns.Msg {
	name := fmt.Sprintf("host%d.zone%d.example%d.test.", i%97, i, i%13)
	signer := fmt.Sprintf("zone%d.example%d.test.", i, i%13)
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	ttl := uint32(600 + i%3000) //nolint:gosec // small
	now := time.Now()
	sig := func(owner string, covered uint16) *dns.RRSIG {
		b := make([]byte, 64)
		_, _ = rand.Read(b)
		return &dns.RRSIG{
			Hdr:         dns.RR_Header{Name: owner, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: ttl},
			TypeCovered: covered, Algorithm: dns.ECDSAP256SHA256, Labels: 4, OrigTtl: ttl,
			Expiration: uint32(now.Add(10 * 24 * time.Hour).Unix()), //nolint:gosec // RFC 4034 serial time
			Inception:  uint32(now.Add(-time.Hour).Unix()),          //nolint:gosec // RFC 4034 serial time
			KeyTag:     uint16(i), SignerName: signer,               //nolint:gosec // any tag
			Signature: base64.StdEncoding.EncodeToString(b),
		}
	}
	a := &dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A: []byte{10, byte(i >> 16), byte(i >> 8), byte(i)}} //nolint:gosec // the low bytes are the point
	switch i % 6 {
	case 0, 1, 2:
		resp.Answer = []dns.RR{a, sig(name, dns.TypeA)}
		resp.AuthenticatedData = true
	case 3, 4:
		resp.Answer = []dns.RR{a}
	default:
		resp.Rcode = dns.RcodeNameError
		soa := &dns.SOA{Hdr: dns.RR_Header{Name: signer, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: ttl},
			Ns: "ns1." + signer, Mbox: "hostmaster." + signer, Serial: 2026092401, Refresh: 7200, Retry: 900, Expire: 1209600, Minttl: ttl}
		nsec := &dns.NSEC{Hdr: dns.RR_Header{Name: "a." + signer, Rrtype: dns.TypeNSEC, Class: dns.ClassINET, Ttl: ttl},
			NextDomain: "z." + signer, TypeBitMap: []uint16{dns.TypeA, dns.TypeRRSIG, dns.TypeNSEC}}
		resp.Ns = []dns.RR{soa, sig(signer, dns.TypeSOA), nsec, sig("a."+signer, dns.TypeNSEC)}
		resp.AuthenticatedData = true
	}
	return resp
}

func cpuTime() time.Duration {
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// memory is the live heap after a collection and the process's peak RSS.
func memory() (heap, peakRSS uint64) {
	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	var ru syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	peakRSS = uint64(ru.Maxrss) //nolint:gosec // non-negative
	if runtime.GOOS != "darwin" {
		peakRSS *= 1024 // Linux reports kilobytes
	}
	return ms.HeapInuse, peakRSS
}

func mb(b uint64) string { return fmt.Sprintf("%.0f MB", float64(b)/1e6) }
