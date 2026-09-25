package cache

import (
	"errors"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

// minSnapshotLifetime is the least an answer must have left to be written:
// one about to expire would be gone before the process is back.
const minSnapshotLifetime = 10 * time.Second

// snapshotSaved counts what Snapshot wrote and why it passed over the rest.
type snapshotSaved struct {
	saved, scoped, short int
	truncated            bool // the walk ran out of time
}

// Snapshot writes the positive answers the cache holds to w. Each keeps the
// lifetime and the delegation lease it had left at the one instant the
// snapshot is taken at, so a restore can age both by exactly the time the
// file spent on disk.
//
// ECS-scoped answers are left out: their audience is a client prefix, and a
// restart is no reason to trust a geo answer longer. So are answers with
// less than minSnapshotLifetime left.
//
// The entries are gathered under the cache's segment locks and written
// after they are released, so a slow disk never holds up a cache write.
// Once stop reports the walk budget spent no further record is written; the
// file is then finished with what it has, a shorter but complete snapshot.
func (s *Store) snapshot(w io.Writer, fingerprint [32]byte, compression uint16, now time.Time, stop func(i int) bool) (snapshotSaved, error) {
	var out snapshotSaved

	entries := make([]*CacheEntry, 0, s.positive.Len())
	s.positive.cache.ForEach(func(_ uint64, value any) bool {
		if e, ok := value.(*CacheEntry); ok && e != nil {
			entries = append(entries, e)
		}
		return true
	})

	sw, err := newSnapshotWriter(w, snapshotHeader{
		compression: compression,
		savedAt:     now,
		fingerprint: fingerprint,
	})
	if err != nil {
		return out, err
	}
	for i, e := range entries {
		if stop(i) {
			out.truncated = true
			break
		}
		if e.scoped() {
			out.scoped++
			continue
		}
		ttl, lease := e.remainingBounds(now)
		if e.cutUntil.IsZero() {
			lease = noLease
		}
		if ttl < minSnapshotLifetime || (lease != noLease && lease < minSnapshotLifetime) {
			out.short++
			continue
		}
		if err := sw.add(&snapshotRecord{
			ttl:      ttl,
			lease:    lease,
			origTTL:  e.origTTL,
			cd:       e.cd,
			compress: e.compress,
			ede:      e.edeOption(),
			wire:     e.wire,
		}); err != nil {
			return out, err
		}
		out.saved++
	}
	return out, sw.finish()
}

// snapshotLoaded counts what Restore admitted and why it passed over the
// rest.
type snapshotLoaded struct {
	loaded, expired, refused int
	full                     bool // stopped at the cache's capacity
}

// Restore admits the answers of a snapshot written by Snapshot, if the file
// is intact and was written under the same fingerprint. It reads the file
// twice: once to verify all of it, the checksum at its end included, and
// only then again to admit, so a damaged file admits nothing. Both passes
// spend the same budget, and a verification that runs out of it admits
// nothing either.
//
// Nothing restored is taken on trust. Each answer ages by the time since
// the snapshot, its lifetime and its lease separately, and goes through
// the admission an answer from the network goes through: classification,
// the TTL the records and their signatures allow now, the configured
// bounds, the signature and AD rules, the policy stamp. The result can
// only be shorter than what was saved, never longer.
//
// spent reports the budget gone, asked before each record of either pass;
// now is the clock the answers are aged against.
func (s *Store) restore(r io.ReadSeeker, fingerprint [32]byte, spent func(n uint64) bool, now func() time.Time) (snapshotLoaded, error) {
	var out snapshotLoaded

	// The wall clock is read once, before anything else, for the one thing
	// only it can say: how long the file has been on disk. Progress from
	// there is measured on the monotonic clock, so a wall-clock step back
	// at any point of the restore, the verifying pass included, cannot make
	// an answer younger, or revive a lease already spent.
	start := now()

	h, err := scanSnapshot(r, spent, nil)
	if err != nil {
		return out, err
	}
	if h.fingerprint != fingerprint {
		return out, errSnapshotFingerprint
	}
	if h.savedAt.After(start) {
		return out, errSnapshotClock
	}
	down := start.Sub(h.savedAt)
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return out, err
	}

	capacity := s.cfg.Size
	_, err = scanSnapshot(r, spent, func(rec *snapshotRecord) bool {
		if capacity > 0 && out.loaded >= capacity {
			out.full = true
			return false
		}
		at := now()
		progress := at.Sub(start)
		if progress < 0 {
			progress = 0
		}
		switch s.restoreRecord(rec, down+progress, at) {
		case restoreAdmitted:
			out.loaded++
		case restoreExpired:
			out.expired++
		default:
			out.refused++
		}
		return true
	})
	return out, err
}

var (
	errSnapshotFingerprint = errors.New("cache snapshot: written under a different configuration")
	errSnapshotClock       = errors.New("cache snapshot: saved in the future")
)

type restoreOutcome int

const (
	restoreAdmitted restoreOutcome = iota
	restoreExpired
	restoreRefused
)

// restoreRecord ages one saved answer by elapsed, the time since it was
// saved, and admits it at now the way setFromResponseWithKey admits a
// response.
func (s *Store) restoreRecord(rec *snapshotRecord, elapsed time.Duration, now time.Time) restoreOutcome {
	ttlLeft := rec.ttl - elapsed
	if ttlLeft <= 0 {
		return restoreExpired
	}
	var cutUntil time.Time
	if rec.lease != noLease {
		leaseLeft := rec.lease - elapsed
		if leaseLeft <= 0 {
			// The lease is the parent's grant, a hard ceiling: an answer past
			// it is neither fresh nor stale, it is gone.
			return restoreExpired
		}
		cutUntil = now.Add(leaseLeft)
	}

	msg := new(dns.Msg)
	if err := msg.Unpack(rec.wire); err != nil || len(msg.Question) != 1 {
		return restoreRefused
	}
	if rec.ede != nil {
		// Admission takes the EDE from the OPT record the upstream sent.
		opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
		opt.Option = []dns.EDNS0{rec.ede}
		msg.Extra = append(msg.Extra, opt)
	}

	mt, _ := dnsutil.ClassifyResponse(msg, now)
	switch mt {
	case dnsutil.TypeSuccess, dnsutil.TypeReferral, dnsutil.TypeNXDomain, dnsutil.TypeNoRecords:
	default:
		return restoreRefused
	}
	filtered := filterCacheableAnswer(msg)
	ttl := s.positive.ttl.Bound(dnsutil.CalculateCacheTTLAt(filtered, mt, now))
	if ttl <= 0 {
		return restoreRefused
	}
	if ttl > ttlLeft {
		ttl = ttlLeft
	}

	key := CacheKey{Question: msg.Question[0], CD: rec.cd}.Hash()
	e := newCacheEntryAt(filtered, ttl, s.cfg.RateLimit, key, now)
	if e == nil {
		return restoreRefused
	}
	e.cd = rec.cd
	e.compress = rec.compress
	e.cutUntil = cutUntil
	// The prefetch threshold is a share of the answer's full lifetime, not
	// of what was left of it at the restart.
	if rec.origTTL > e.origTTL {
		e.origTTL = rec.origTTL
	}
	s.stampSidecar(e, filtered)
	s.positive.Set(key, e)
	return restoreAdmitted
}
