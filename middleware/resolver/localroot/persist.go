package localroot

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/semihalev/sdns/internal/atomicfile"
	"github.com/semihalev/zlog/v2"
)

// The copy on disk is the zone in master file format under one header line
// naming the format and the instant the zone was transferred, and over a
// last line carrying the CRC-32C of everything before it. The zone passes
// the same ZONEMD verification a live transfer does, and its horizon runs
// from the transfer, so a restart neither extends a copy's life nor keeps
// one past its SOA expire. The checksum is what covers the header, which
// ZONEMD does not, and it turns away a damaged file before any of it is
// parsed or verified.
const (
	copyHeader = "; sdns local root copy v1, fetched at"
	copyFooter = "; crc32c"
)

var (
	castagnoli = crc32.MakeTable(crc32.Castagnoli)
	// maxCopyBytes bounds what Restore reads: the transfer limit, doubled
	// for the text form's overhead over the wire.
	maxCopyBytes = 2 * rootTransferLimits.MaxBytes
)

var metricDisk = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "dns_localroot_disk_total",
	Help: "Local root copy disk operations by operation and result",
}, []string{"op", "result"})

var (
	errCopyHeader   = errors.New("local root copy: unrecognized header")
	errCopyClock    = errors.New("local root copy: fetched in the future")
	errCopySize     = errors.New("local root copy: too large")
	errCopyChecksum = errors.New("local root copy: checksum mismatch")
)

// SetCopyPath keeps the verified copy at path across restarts: Restore reads
// it back, and every copy that goes live is written there. Call it before
// Restore and Run.
func (m *Manager) SetCopyPath(path string) { m.copyPath = path }

// Restore installs the copy an earlier run left on disk, subject to the same
// verification as a transfer, against the trust anchors the resolver holds
// now. It runs before the refresh loop starts and never replaces a copy that
// is already live. Any failure leaves the manager as it was: the refresh
// loop transfers a fresh copy as it would on a first start.
func (m *Manager) Restore() {
	if m.copyPath == "" {
		return
	}
	result, err := m.restore()
	metricDisk.WithLabelValues("load", result).Inc()
	switch {
	case result == "ok":
		zlog.Info("Local root copy restored from disk", "path", m.copyPath, "serial", m.snap.Load().serial)
	case err != nil:
		zlog.Warn("Local root copy on disk not used", "path", m.copyPath, "reason", result, "error", err.Error())
	}
}

func (m *Manager) restore() (string, error) {
	f, err := os.Open(m.copyPath)
	if errors.Is(err, os.ErrNotExist) {
		return "absent", nil
	}
	if err != nil {
		return "read_error", err
	}
	defer f.Close() //nolint:errcheck // read-only

	fetched, rrs, err := decodeCopy(f, m.copyPath)
	if err != nil {
		return "corrupt", err
	}
	now := m.now()
	if fetched.After(now) {
		// The clock went back, or the file was written by a clock that ran
		// ahead. Either way the copy's age cannot be known.
		return "clock", errCopyClock
	}

	snap, outcome, err := m.verify(normalizeZone(rrs), fetched)
	if err != nil {
		return outcome, err
	}
	if snap.Expired(now) {
		return "expired", nil
	}

	m.publish.Lock()
	defer m.publish.Unlock()
	if m.snap.Load() != nil {
		return "superseded", nil
	}
	m.snap.Store(snap)
	m.published++
	return "ok", nil
}

// diskCopy is one published copy waiting to be written.
type diskCopy struct {
	rrs     []dns.RR
	fetched time.Time
}

// diskWriter hands published copies to a single writer, newest only. Writes
// are serialized by that writer, but the offers reach it from whichever load
// published them, and a load can be slower to offer than a later one. So an
// offer is accepted only if it is newer than every offer accepted before it,
// not merely newer than whatever is waiting: the slot may already be empty
// because the newer copy was taken and written.
type diskWriter struct {
	mu       sync.Mutex
	accepted uint64 // highest sequence ever accepted
	pending  *diskCopy
	wake     chan struct{}
}

func (w *diskWriter) offer(seq uint64, c *diskCopy) bool {
	w.mu.Lock()
	if seq <= w.accepted {
		w.mu.Unlock()
		return false
	}
	w.accepted = seq
	w.pending = c
	w.mu.Unlock()
	select {
	case w.wake <- struct{}{}:
	default:
	}
	return true
}

func (w *diskWriter) take() *diskCopy {
	w.mu.Lock()
	defer w.mu.Unlock()
	c := w.pending
	w.pending = nil
	return c
}

// writeLoop writes offered copies until ctx is cancelled. A failed write is
// counted and logged and otherwise ignored: the copy in memory is unaffected,
// and the next published copy is written in full.
func (m *Manager) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.disk.wake:
		}
		c := m.disk.take()
		if c == nil {
			continue
		}
		if err := atomicfile.Write(m.copyPath, func(w io.Writer) error {
			return encodeCopy(w, c)
		}); err != nil {
			metricDisk.WithLabelValues("write", "error").Inc()
			zlog.Warn("Local root copy write failed", "path", m.copyPath, "error", err.Error())
			continue
		}
		metricDisk.WithLabelValues("write", "ok").Inc()
	}
}

func encodeCopy(w io.Writer, c *diskCopy) error {
	sum := crc32.New(castagnoli)
	body := io.MultiWriter(w, sum)
	if _, err := fmt.Fprintf(body, "%s %d\n", copyHeader, c.fetched.UnixNano()); err != nil {
		return err
	}
	for _, rr := range c.rrs {
		if _, err := io.WriteString(body, rr.String()); err != nil {
			return err
		}
		if _, err := io.WriteString(body, "\n"); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintf(w, "%s %08x\n", copyFooter, sum.Sum32())
	return err
}

func decodeCopy(r io.Reader, name string) (time.Time, []dns.RR, error) {
	data, err := io.ReadAll(io.LimitReader(r, int64(maxCopyBytes)+1))
	if err != nil {
		return time.Time{}, nil, err
	}
	if len(data) > maxCopyBytes {
		return time.Time{}, nil, errCopySize
	}
	// The footer is the last line; the checksum covers every byte before it.
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return time.Time{}, nil, errCopyChecksum
	}
	cut := bytes.LastIndexByte(data[:len(data)-1], '\n') + 1
	body, footer := data[:cut], strings.TrimSuffix(string(data[cut:]), "\n")
	want, ok := strings.CutPrefix(footer, copyFooter+" ")
	if !ok {
		return time.Time{}, nil, errCopyChecksum
	}
	if got := fmt.Sprintf("%08x", crc32.Checksum(body, castagnoli)); got != want {
		return time.Time{}, nil, errCopyChecksum
	}

	br := bufio.NewReader(bytes.NewReader(body))
	line, err := br.ReadString('\n')
	if err != nil {
		return time.Time{}, nil, errCopyHeader
	}
	stamp, ok := strings.CutPrefix(strings.TrimSuffix(line, "\n"), copyHeader+" ")
	if !ok {
		return time.Time{}, nil, errCopyHeader
	}
	nanos, err := strconv.ParseInt(stamp, 10, 64)
	if err != nil {
		return time.Time{}, nil, errCopyHeader
	}

	zp := dns.NewZoneParser(br, ".", name)
	var rrs []dns.RR
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if len(rrs) >= rootTransferLimits.MaxRecords {
			return time.Time{}, nil, errCopySize
		}
		rrs = append(rrs, rr)
	}
	if err := zp.Err(); err != nil {
		return time.Time{}, nil, err
	}
	return time.Unix(0, nanos), rrs, nil
}
