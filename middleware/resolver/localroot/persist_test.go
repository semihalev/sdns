package localroot

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/resolver/localroot/roottest"
)

func copyManager(t *testing.T, anchors []dns.RR, path string, now time.Time) *Manager {
	t.Helper()
	m := New(nil, func() []dns.RR { return anchors })
	m.now = func() time.Time { return now }
	m.SetCopyPath(path)
	return m
}

func writeCopyFile(t *testing.T, path string, rrs []dns.RR, fetched time.Time) {
	t.Helper()
	var buf bytes.Buffer
	if err := encodeCopy(&buf, &diskCopy{rrs: rrs, fetched: fetched}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// waitForCopy waits until the file at path holds the zone with serial.
func waitForCopy(t *testing.T, path string, serial uint32) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if f, err := os.Open(path); err == nil { //nolint:gosec // test-owned temp path
			_, rrs, err := decodeCopy(f, path)
			_ = f.Close()
			if err == nil {
				for _, rr := range rrs {
					if soa, ok := rr.(*dns.SOA); ok && soa.Serial == serial {
						return
					}
				}
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no copy with serial %d reached %s", serial, path)
}

func restoreResult(t *testing.T, m *Manager) string {
	t.Helper()
	result, _ := m.restore()
	return result
}

// A copy written by one run is what the next run serves from, and it keeps
// the age it had: the horizon and the refresh schedule both run from the
// transfer, not from the restart.
func TestCopySurvivesRestart(t *testing.T) {
	root := buildTestRoot(t)
	path := filepath.Join(t.TempDir(), "root.zone")
	fetched := time.Now().Add(-10 * time.Minute)

	first := copyManager(t, root.anchors, path, fetched)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go first.writeLoop(ctx)
	if err := first.Load(root.rrs); err != nil {
		t.Fatal(err)
	}
	waitForCopy(t, path, root.serial)
	live := first.Active()

	second := copyManager(t, root.anchors, path, time.Now())
	if got := restoreResult(t, second); got != "ok" {
		t.Fatalf("restore = %q, want ok", got)
	}
	restored := second.Active()
	if restored == nil {
		t.Fatal("the restored copy is not active")
	}
	if restored.Serial() != root.serial {
		t.Fatalf("serial = %d, want %d", restored.Serial(), root.serial)
	}
	if !restored.Loaded().Equal(live.Loaded()) {
		t.Fatalf("restored copy dated %v, want its transfer time %v", restored.Loaded(), live.Loaded())
	}
	// The live copy counts its SOA expire on the monotonic clock; a restart
	// has only the transfer's calendar time to count from. Both must end at
	// the same instant.
	now := time.Now()
	if d := horizonLeft(restored, now) - horizonLeft(live, now); d < -time.Millisecond || d > time.Millisecond {
		t.Fatalf("horizon %+v, want the one set at transfer %+v", restored.ValidUntil(), live.ValidUntil())
	}
}

// horizonLeft is how long the copy has left at now.
func horizonLeft(s *Snapshot, now time.Time) time.Duration {
	left, _ := s.ValidUntil().Remaining(now)
	return left
}

// The SOA expire horizon is measured from the transfer. A copy whose expire
// passed while the process was down is not served, and one still inside it
// keeps only what is left.
func TestRestoreHorizonRunsFromTheTransfer(t *testing.T) {
	root := buildTestRoot(t)
	lines := roottest.DefaultLines(root.serial)
	// Expire 1200s, inside the fixture's one hour signature window, so the
	// SOA expire is the bound that decides.
	lines[0] = strings.Replace(lines[0], " 604800 ", " 1200 ", 1)
	z, err := roottest.BuildZoneWithKey(ComputeDigest, lines, root.serial, root.key, root.priv)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	t.Run("expired while down", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "root.zone")
		writeCopyFile(t, path, z.RRs, now.Add(-1500*time.Second))
		m := copyManager(t, root.anchors, path, now)
		if got := restoreResult(t, m); got != "expired" {
			t.Fatalf("restore = %q, want expired", got)
		}
		if m.Active() != nil {
			t.Fatal("a copy past its SOA expire was restored")
		}
	})

	t.Run("inside the horizon", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "root.zone")
		fetched := now.Add(-600 * time.Second)
		writeCopyFile(t, path, z.RRs, fetched)
		m := copyManager(t, root.anchors, path, now)
		if got := restoreResult(t, m); got != "ok" {
			t.Fatalf("restore = %q, want ok", got)
		}
		s := m.Active()
		if s == nil {
			t.Fatal("a copy inside its horizon was not restored")
		}
		if want := fetched.Add(1200 * time.Second); horizonLeft(s, now) != want.Sub(now) {
			t.Fatalf("horizon %+v, want transfer + expire %v", s.ValidUntil(), want)
		}
	})
}

// Everything that would refuse a transfer refuses a copy on disk, and so do
// the ways a file can be damaged. None of them leaves anything active.
func TestRestoreRefuses(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()
	fetched := now.Add(-time.Minute)

	tampered := make([]dns.RR, 0, len(root.rrs))
	for _, rr := range root.rrs {
		rr = dns.Copy(rr)
		if a, ok := rr.(*dns.A); ok && a.Hdr.Name == "ns.com." {
			a.A = a.A.To4()
			a.A[3]++
		}
		tampered = append(tampered, rr)
	}
	other := buildTestRoot(t)

	valid := func(t *testing.T, path string) {
		writeCopyFile(t, path, root.rrs, fetched)
	}
	rewrite := func(t *testing.T, path string, edit func([]byte) []byte) {
		t.Helper()
		b, err := os.ReadFile(path) //nolint:gosec // test-owned temp path
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, edit(b), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cases := []struct {
		name    string
		anchors []dns.RR
		write   func(t *testing.T, path string)
		want    string
	}{
		{"absent", root.anchors, func(*testing.T, string) {}, "absent"},
		{"a record changed under a valid checksum", root.anchors, func(t *testing.T, path string) {
			writeCopyFile(t, path, tampered, fetched)
		}, "verify_error"},
		{"the trust anchors moved on", other.anchors, valid, "verify_error"},
		{"fetched in the future", root.anchors, func(t *testing.T, path string) {
			writeCopyFile(t, path, root.rrs, now.Add(time.Minute))
		}, "clock"},
		{"one byte flipped", root.anchors, func(t *testing.T, path string) {
			valid(t, path)
			rewrite(t, path, func(b []byte) []byte {
				i := bytes.Index(b, []byte("ns.com."))
				b[i] = 'm'
				return b
			})
		}, "corrupt"},
		{"the header's transfer time changed", root.anchors, func(t *testing.T, path string) {
			valid(t, path)
			rewrite(t, path, func(b []byte) []byte {
				i := bytes.IndexByte(b, '\n')
				b[i-1] = '0' + (b[i-1]-'0'+1)%10
				return b
			})
		}, "corrupt"},
		{"truncated", root.anchors, func(t *testing.T, path string) {
			valid(t, path)
			rewrite(t, path, func(b []byte) []byte { return b[:len(b)/2] })
		}, "corrupt"},
		{"an unknown format", root.anchors, func(t *testing.T, path string) {
			valid(t, path)
			rewrite(t, path, func(b []byte) []byte {
				return bytes.Replace(b, []byte("copy v1"), []byte("copy v9"), 1)
			})
		}, "corrupt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "root.zone")
			tc.write(t, path)
			m := copyManager(t, tc.anchors, path, now)
			if got := restoreResult(t, m); got != tc.want {
				t.Fatalf("restore = %q, want %q", got, tc.want)
			}
			if m.snap.Load() != nil {
				t.Fatal("a refused copy was installed")
			}
		})
	}
}

// Restore fills an empty manager only. A copy that is already live, even of
// the same serial, is never replaced by an older transfer from disk.
func TestRestoreNeverReplacesALiveCopy(t *testing.T) {
	root := buildTestRoot(t)
	now := time.Now()
	path := filepath.Join(t.TempDir(), "root.zone")
	writeCopyFile(t, path, root.rrs, now.Add(-30*time.Minute))

	m := copyManager(t, root.anchors, path, now)
	if err := m.Load(root.rrs); err != nil {
		t.Fatal(err)
	}
	live := m.Active()

	if got := restoreResult(t, m); got != "superseded" {
		t.Fatalf("restore = %q, want superseded", got)
	}
	if m.Active() != live {
		t.Fatal("restore replaced the live copy")
	}
}

// Two loads can reach the disk writer in the opposite order they went live.
// The older one arriving last must not overwrite the newer copy on disk,
// even after the newer one was taken off the slot and written.
func TestDiskWriterKeepsTheNewestCopy(t *testing.T) {
	root := buildTestRoot(t)
	newer, err := roottest.BuildZoneWithKey(
		ComputeDigest, roottest.DefaultLines(root.serial+1), root.serial+1, root.key, root.priv,
	)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "root.zone")
	m := copyManager(t, root.anchors, path, time.Now())

	held := make(chan struct{})
	release := make(chan struct{})
	m.beforeOffer = func(seq uint64) {
		if seq == 1 {
			close(held)
			<-release
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go m.writeLoop(ctx)

	olderDone := make(chan error, 1)
	go func() { olderDone <- m.Load(root.rrs) }()
	<-held

	if err := m.Load(newer.RRs); err != nil {
		t.Fatal(err)
	}
	waitForCopy(t, path, root.serial+1)

	close(release)
	if err := <-olderDone; err != nil {
		t.Fatal(err)
	}
	if m.disk.take() != nil {
		t.Fatal("the older copy was accepted for writing after the newer one")
	}
	time.Sleep(50 * time.Millisecond)
	waitForCopy(t, path, root.serial+1)
}
