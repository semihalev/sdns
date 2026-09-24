package cache

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

var testFingerprint = [32]byte{1, 2, 3}

func newSnapshotStore(t *testing.T, size int, maxTTL time.Duration) *Store {
	t.Helper()
	cfg := CacheConfig{
		Size:        size,
		PositiveTTL: maxTTL,
		NegativeTTL: maxTTL,
		MinTTL:      time.Second,
		MaxTTL:      maxTTL,
	}
	metrics := &CacheMetrics{}
	return NewStore(
		NewPositiveCache(size, cfg.MinTTL, cfg.MaxTTL, metrics),
		NewNegativeCache(1, cfg.MinTTL, cfg.NegativeTTL, metrics),
		cfg,
	)
}

func snapAnswer(name string, ttl uint32, ip string) *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}}
	return resp
}

func never(uint64) bool { return false }

func saveSnapshot(t *testing.T, s *Store, compression uint16, now time.Time) []byte {
	t.Helper()
	var b bytes.Buffer
	if _, err := s.snapshot(&b, testFingerprint, compression, now, func(int) bool { return false }); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func loadSnapshot(s *Store, data []byte, at time.Time) (snapshotLoaded, error) {
	return s.restore(bytes.NewReader(data), testFingerprint, never, func() time.Time { return at })
}

func storedEntry(s *Store, name string, cd bool) *CacheEntry {
	e, _ := s.positive.retained(CacheKey{Question: dns.Question{Name: name, Qtype: dns.TypeA, Qclass: dns.ClassINET}, CD: cd}.Hash())
	return e
}

var compressions = []struct {
	name string
	c    uint16
}{{"raw", snapshotRaw}, {"lz4", snapshotLZ4}}

// A restored answer keeps only the lifetime it had left, less the time the
// snapshot spent on disk, and its original TTL for the prefetch threshold.
func TestSnapshotAgesTheLifetime(t *testing.T) {
	for _, c := range compressions {
		t.Run(c.name, func(t *testing.T) {
			src := newSnapshotStore(t, 1024, time.Hour)
			src.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Time{})
			saved := time.Now()
			data := saveSnapshot(t, src, c.c, saved)

			dst := newSnapshotStore(t, 1024, time.Hour)
			at := saved.Add(50 * time.Second)
			got, err := loadSnapshot(dst, data, at)
			if err != nil || got.loaded != 1 {
				t.Fatalf("restore = %+v, %v; want one loaded", got, err)
			}
			e := storedEntry(dst, "a.test.", false)
			if e == nil {
				t.Fatal("restored answer missing")
			}
			if rem := e.remaining(at); rem > 250*time.Second || rem < 249*time.Second {
				t.Fatalf("remaining %v at restore, want 300s less 50s down", rem)
			}
			if e.origTTL != 300 {
				t.Fatalf("origTTL %d, want 300", e.origTTL)
			}
		})
	}
}

func TestSnapshotDropsWhatExpiredWhileDown(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	src.SetFromResponse(snapAnswer("a.test.", 30, "192.0.2.1"), false, time.Time{})
	saved := time.Now()
	data := saveSnapshot(t, src, snapshotLZ4, saved)

	dst := newSnapshotStore(t, 1024, time.Hour)
	got, err := loadSnapshot(dst, data, saved.Add(40*time.Second))
	if err != nil || got.loaded != 0 || got.expired != 1 {
		t.Fatalf("restore = %+v, %v; want the one answer expired", got, err)
	}
	if dst.PositiveLen() != 0 {
		t.Fatal("an answer that expired while down was restored")
	}
}

// The delegation lease ages on its own clock. An answer whose lease ran out
// while the process was down is gone, not stale: nothing is left for
// serve-stale to find.
func TestSnapshotAgesTheLeaseSeparately(t *testing.T) {
	restoreWithLease := func(t *testing.T, lease, down time.Duration) (*Store, time.Time) {
		t.Helper()
		src := newSnapshotStore(t, 1024, time.Hour)
		src.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Now().Add(lease))
		saved := time.Now()
		data := saveSnapshot(t, src, snapshotLZ4, saved)
		dst := newSnapshotStore(t, 1024, time.Hour)
		at := saved.Add(down)
		if _, err := loadSnapshot(dst, data, at); err != nil {
			t.Fatal(err)
		}
		return dst, at
	}

	t.Run("lease shortened by the downtime", func(t *testing.T) {
		dst, at := restoreWithLease(t, 60*time.Second, 50*time.Second)
		e := storedEntry(dst, "a.test.", false)
		if e == nil {
			t.Fatal("answer with lease left was not restored")
		}
		_, lease := e.remainingBounds(at)
		if lease > 10*time.Second || lease < 9*time.Second {
			t.Fatalf("lease left %v, want 60s less 50s down", lease)
		}
		if rem := e.remaining(at); rem > 10*time.Second {
			t.Fatalf("the lease no longer bounds the answer: %v left", rem)
		}
	})

	t.Run("lease ran out while down", func(t *testing.T) {
		dst, _ := restoreWithLease(t, 60*time.Second, 70*time.Second)
		if storedEntry(dst, "a.test.", false) != nil {
			t.Fatal("an answer past its lease was restored, fresh or stale")
		}
	})

	t.Run("no lease stays no lease", func(t *testing.T) {
		src := newSnapshotStore(t, 1024, time.Hour)
		src.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Time{})
		saved := time.Now()
		dst := newSnapshotStore(t, 1024, time.Hour)
		if _, err := loadSnapshot(dst, saveSnapshot(t, src, snapshotLZ4, saved), saved.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if e := storedEntry(dst, "a.test.", false); e == nil || !e.cutUntil.IsZero() {
			t.Fatal("an answer without a lease came back with one, or not at all")
		}
	})
}

// The time on disk is read from the wall clock once; a step back during the
// restore cannot make an answer younger. Here the restore starts 70 seconds
// after the save and every later reading claims 50: a 60 second lease spent
// at the start stays spent.
func TestSnapshotRestoreSurvivesAClockStepBack(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	src.SetFromResponse(snapAnswer("a.test.", 300, "192.0.2.1"), false, time.Now().Add(60*time.Second))
	src.SetFromResponse(snapAnswer("b.test.", 60, "192.0.2.1"), false, time.Time{})
	saved := time.Now()
	data := saveSnapshot(t, src, snapshotLZ4, saved)

	// Wall readings only, as a stepped clock produces: no monotonic part.
	wall := func(d time.Duration) time.Time { return time.Unix(0, saved.Add(d).UnixNano()) }
	readings := 0
	clock := func() time.Time {
		readings++
		if readings == 1 {
			return wall(70 * time.Second)
		}
		return wall(50 * time.Second)
	}

	dst := newSnapshotStore(t, 1024, time.Hour)
	got, err := dst.restore(bytes.NewReader(data), testFingerprint, never, clock)
	if err != nil {
		t.Fatal(err)
	}
	if got.loaded != 0 || dst.PositiveLen() != 0 {
		t.Fatalf("a clock step back revived %d answers: %+v", dst.PositiveLen(), got)
	}
}

// A file that fails any check admits nothing at all.
func TestSnapshotRefusedWhole(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	for _, n := range []string{"a.test.", "b.test.", "c.test."} {
		src.SetFromResponse(snapAnswer(n, 300, "192.0.2.1"), false, time.Time{})
	}
	saved := time.Now()
	raw := saveSnapshot(t, src, snapshotRaw, saved)
	lz := saveSnapshot(t, src, snapshotLZ4, saved)

	edit := func(data []byte, f func([]byte) []byte) []byte {
		return f(append([]byte(nil), data...))
	}
	cases := []struct {
		name string
		data []byte
		fp   [32]byte
		at   time.Time
	}{
		{"a body byte flipped", edit(raw, func(b []byte) []byte { b[len(b)-20] ^= 1; return b }), testFingerprint, saved},
		{"a compressed byte flipped", edit(lz, func(b []byte) []byte { b[len(b)-20] ^= 1; return b }), testFingerprint, saved},
		{"the saved time changed", edit(raw, func(b []byte) []byte { b[13] ^= 1; return b }), testFingerprint, saved.Add(time.Hour)},
		{"truncated", raw[:len(raw)/2], testFingerprint, saved},
		{"truncated compressed", lz[:len(lz)/2], testFingerprint, saved},
		// The records and their CRC intact, the LZ4 frame around them not.
		{"compressed, last byte gone", lz[:len(lz)-1], testFingerprint, saved},
		{"compressed, last eight bytes gone", lz[:len(lz)-8], testFingerprint, saved},
		{"compressed, frame checksum flipped", edit(lz, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), testFingerprint, saved},
		{"compressed, trailing byte", append(append([]byte(nil), lz...), 0xff), testFingerprint, saved},
		// The frame's end mark and checksum cut out with the trailer kept,
		// which the decompressor alone reads to a clean end.
		{"compressed, frame end cut, trailer kept", frameEndCut(lz), testFingerprint, saved},
		// A byte between the body and the trailer lies past the body's
		// recorded length, where no reader of the body looks.
		{"a byte before the trailer", beforeTrailer(raw), testFingerprint, saved},
		{"compressed, a byte before the trailer", beforeTrailer(lz), testFingerprint, saved},
		{"trailing bytes", append(append([]byte(nil), raw...), 0), testFingerprint, saved},
		{"another format version", edit(raw, func(b []byte) []byte { b[8] = 9; return b }), testFingerprint, saved},
		{"another configuration", raw, [32]byte{9}, saved},
		{"saved in the future", raw, testFingerprint, saved.Add(-time.Minute)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dst := newSnapshotStore(t, 1024, time.Hour)
			got, err := dst.restore(bytes.NewReader(tc.data), tc.fp, never, func() time.Time { return tc.at })
			if err == nil {
				t.Fatalf("restore accepted it: %+v", got)
			}
			if dst.PositiveLen() != 0 || got.loaded != 0 {
				t.Fatalf("a refused file admitted %d answers", dst.PositiveLen())
			}
		})
	}
}

// frameEndCut removes the LZ4 frame's last eight bytes, its end mark and
// content checksum, from a snapshot and puts the trailer back after it.
func frameEndCut(file []byte) []byte {
	trailer := file[len(file)-snapshotTrailerLen:]
	out := append([]byte(nil), file[:len(file)-snapshotTrailerLen-8]...)
	return append(out, trailer...)
}

// beforeTrailer inserts one byte between a snapshot's body and its trailer.
func beforeTrailer(file []byte) []byte {
	body := file[:len(file)-snapshotTrailerLen]
	out := append(append([]byte(nil), body...), 0)
	return append(out, file[len(file)-snapshotTrailerLen:]...)
}

// Both passes share one budget. Spent before verification finishes, it
// admits nothing; spent during admission, it keeps what was admitted.
func TestSnapshotRestoreBudget(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	const n = 10
	for i := range n {
		src.SetFromResponse(snapAnswer(string(rune('a'+i))+".test.", 300, "192.0.2.1"), false, time.Time{})
	}
	saved := time.Now()
	data := saveSnapshot(t, src, snapshotLZ4, saved)
	at := func() time.Time { return saved }

	t.Run("spent while verifying", func(t *testing.T) {
		dst := newSnapshotStore(t, 1024, time.Hour)
		calls := 0
		got, err := dst.restore(bytes.NewReader(data), testFingerprint, func(uint64) bool {
			calls++
			return calls > n/2
		}, at)
		if !errors.Is(err, errSnapshotBudget) || got.loaded != 0 || dst.PositiveLen() != 0 {
			t.Fatalf("restore = %+v, %v with %d admitted; want nothing", got, err, dst.PositiveLen())
		}
	})

	t.Run("spent while admitting", func(t *testing.T) {
		dst := newSnapshotStore(t, 1024, time.Hour)
		const keep = 4
		calls := 0
		// The verifying pass asks once per record and once at the end.
		got, err := dst.restore(bytes.NewReader(data), testFingerprint, func(uint64) bool {
			calls++
			return calls > (n+1)+keep
		}, at)
		if !errors.Is(err, errSnapshotBudget) || got.loaded != keep || dst.PositiveLen() != keep {
			t.Fatalf("restore = %+v, %v with %d admitted; want %d kept", got, err, dst.PositiveLen(), keep)
		}
	})
}

func TestSnapshotStopsAtCapacity(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	for i := range 10 {
		src.SetFromResponse(snapAnswer(string(rune('a'+i))+".test.", 300, "192.0.2.1"), false, time.Time{})
	}
	saved := time.Now()
	dst := newSnapshotStore(t, 4, time.Hour)
	got, err := loadSnapshot(dst, saveSnapshot(t, src, snapshotLZ4, saved), saved)
	if err != nil || got.loaded != 4 || !got.full {
		t.Fatalf("restore = %+v, %v; want four loaded and full", got, err)
	}
}

// ECS-scoped answers and answers about to expire are not written, and a
// walk out of time still leaves a complete file.
func TestSnapshotLeavesOut(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	src.SetFromResponse(snapAnswer("kept.test.", 300, "192.0.2.1"), false, time.Time{})
	src.SetFromResponse(snapAnswer("short.test.", 5, "192.0.2.1"), false, time.Time{})
	scoped := snapAnswer("scoped.test.", 300, "192.0.2.1")
	scope := netip.MustParsePrefix("198.51.100.0/24")
	src.SetFromResponseScoped(CacheKey{Question: scoped.Question[0], Scope: scope}.Hash(), scoped, scope, time.Time{}, 0)

	var b bytes.Buffer
	saved, err := src.snapshot(&b, testFingerprint, snapshotLZ4, time.Now(), func(int) bool { return false })
	if err != nil || saved.saved != 1 || saved.short != 1 || saved.scoped != 1 {
		t.Fatalf("snapshot = %+v, %v; want one saved, one short, one scoped", saved, err)
	}

	b.Reset()
	saved, err = src.snapshot(&b, testFingerprint, snapshotLZ4, time.Now(), func(int) bool { return true })
	if err != nil || !saved.truncated || saved.saved != 0 {
		t.Fatalf("snapshot = %+v, %v; want an empty, truncated walk", saved, err)
	}
	dst := newSnapshotStore(t, 1024, time.Hour)
	if got, err := loadSnapshot(dst, b.Bytes(), time.Now()); err != nil || got.loaded != 0 {
		t.Fatalf("a truncated walk did not leave a valid file: %+v, %v", got, err)
	}
}

// A restored answer goes through admission again: the limits configured
// now apply, and they can only shorten what was saved.
func TestSnapshotRestoreAppliesTodaysLimits(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	src.SetFromResponse(snapAnswer("a.test.", 3600, "192.0.2.1"), false, time.Time{})
	saved := time.Now()
	data := saveSnapshot(t, src, snapshotLZ4, saved)

	dst := newSnapshotStore(t, 1024, time.Minute)
	if _, err := loadSnapshot(dst, data, saved); err != nil {
		t.Fatal(err)
	}
	e := storedEntry(dst, "a.test.", false)
	if e == nil || e.remaining(saved) > time.Minute {
		t.Fatal("a restored answer outlived today's maxttl")
	}
}

// The key is rebuilt from the answer's question and its CD partition, so
// the two partitions of one name come back apart.
func TestSnapshotKeepsTheCDPartition(t *testing.T) {
	src := newSnapshotStore(t, 1024, time.Hour)
	checking := snapAnswer("a.test.", 300, "192.0.2.1")
	disabled := snapAnswer("a.test.", 300, "192.0.2.2")
	disabled.CheckingDisabled = true
	src.SetFromResponse(checking, false, time.Time{})
	src.SetFromResponse(disabled, true, time.Time{})
	saved := time.Now()

	dst := newSnapshotStore(t, 1024, time.Hour)
	if got, err := loadSnapshot(dst, saveSnapshot(t, src, snapshotLZ4, saved), saved); err != nil || got.loaded != 2 {
		t.Fatalf("restore = %+v, %v; want both partitions", got, err)
	}
	for _, tc := range []struct {
		cd bool
		ip string
	}{{false, "192.0.2.1"}, {true, "192.0.2.2"}} {
		req := new(dns.Msg)
		req.SetQuestion("a.test.", dns.TypeA)
		req.CheckingDisabled = tc.cd
		resp, ok := dst.Get(req)
		if !ok || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != tc.ip {
			t.Fatalf("CD=%v: got %v, want %s", tc.cd, resp, tc.ip)
		}
	}
}

// What a restored entry serves is what the original served: the same wire
// image, the same DO=0 body, the same serving verdicts, the same EDE and
// compression, with the policy stamp taken again.
func TestSnapshotRestoresTheSameEntry(t *testing.T) {
	_, signed := signedAnswer("signed.test.", 300, 300, 300, time.Hour)
	signed.AuthenticatedData = true
	withEDE := snapAnswer("ede.test.", 300, "192.0.2.1")
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.Option = []dns.EDNS0{&dns.EDNS0_EDE{InfoCode: dns.ExtendedErrorCodeStaleAnswer, ExtraText: "kept"}}
	withEDE.Extra = append(withEDE.Extra, opt)
	withEDE.Compress = true

	src := newSnapshotStore(t, 1024, time.Hour)
	src.SetFromResponse(signed, false, time.Time{})
	src.SetFromResponse(withEDE, false, time.Time{})
	saved := time.Now()
	data := saveSnapshot(t, src, snapshotLZ4, saved)

	dst := newSnapshotStore(t, 1024, time.Hour)
	stamped := 0
	dst.SetSidecarEvaluator(func(*dns.Msg) *middleware.Sidecar {
		stamped++
		return nil
	})
	if got, err := loadSnapshot(dst, data, saved); err != nil || got.loaded != 2 {
		t.Fatalf("restore = %+v, %v", got, err)
	}
	if stamped != 2 {
		t.Fatalf("policy stamped %d restored answers, want 2", stamped)
	}

	for _, name := range []string{"signed.test.", "ede.test."} {
		was, now := storedEntry(src, name, false), storedEntry(dst, name, false)
		if was == nil || now == nil {
			t.Fatalf("%s: entry missing", name)
		}
		if !bytes.Equal(was.wire, now.wire) || !bytes.Equal(was.stripped, now.stripped) {
			t.Fatalf("%s: restored bytes differ from the original", name)
		}
		if was.wireServe != now.wireServe || was.strippedServe != now.strippedServe {
			t.Fatalf("%s: serving verdicts differ", name)
		}
		if was.compress != now.compress {
			t.Fatalf("%s: compression flag lost", name)
		}
	}
	if e := storedEntry(dst, "signed.test.", false); e.stripped == nil {
		t.Fatal("the signed answer lost its DO=0 body")
	}
	e := storedEntry(dst, "ede.test.", false)
	if e.ede == nil || e.ede.InfoCode != dns.ExtendedErrorCodeStaleAnswer || e.ede.ExtraText != "kept" {
		t.Fatalf("EDE lost: %+v", e.ede)
	}
}
