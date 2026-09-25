package cache

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/pierrec/lz4/v4"
)

// The snapshot file carries answers across a restart. Its layout:
//
//	header, never compressed:
//	  magic "SDNSCSNP", format version u16, compression u16,
//	  saved-at Unix nanoseconds i64, configuration fingerprint [32]byte
//	body, LZ4 frame or raw per the header:
//	  records, each tagged 1
//	  tag 0, record count u64
//	  CRC-32C u32 over the header and every body byte before it
//	trailer, never compressed:
//	  magic "SDNSCEND", the body's length on disk u64
//
// The trailer is what makes the file's own extent checkable. A file whose
// size is not header, body and trailer to the byte was cut short or added
// to, and the body is read through exactly its recorded length, so the
// decompressor never decides where the file ends: an LZ4 frame that stops
// at a block boundary reads to it as a clean end.
//
// A record holds what the entry's wire image does not: how much of its
// lifetime and of its delegation lease were left at the saved-at instant,
// the calendar instant a wall-clock bound on the lease ends at, its
// original TTL, its CD bit and compression flag, and its EDE. Integers are
// little endian.
const (
	snapshotMagic   = "SDNSCSNP"
	snapshotVersion = 2

	snapshotRaw = 0
	snapshotLZ4 = 1

	snapshotHeaderLen = 8 + 2 + 2 + 8 + 32

	snapshotTrailerMagic = "SDNSCEND"
	snapshotTrailerLen   = 8 + 8

	snapshotRecordTag = 1
	snapshotEndTag    = 0

	// recFixedLen: tag, ttl, lease, wall, origTTL, flags, wire length.
	recFixedLen = 1 + 8 + 8 + 8 + 4 + 1 + 4

	recFlagCD       = 1 << 0
	recFlagCompress = 1 << 1
	recFlagEDE      = 1 << 2

	// noLease marks an entry without a delegation lease, distinct from a
	// lease that has run out, which is never written.
	noLease = -1

	// maxSnapshotFileBytes and maxSnapshotStreamBytes bound, separately,
	// the file a restore opens and the body it decompresses from it, so
	// neither a large file nor a small one that inflates can run on.
	maxSnapshotFileBytes   = 4 << 30
	maxSnapshotStreamBytes = 4 << 30
	// maxSnapshotWire is a DNS message's own ceiling.
	maxSnapshotWire = dns.MaxMsgSize
)

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

var (
	errSnapshotHeader   = errors.New("cache snapshot: unrecognized header")
	errSnapshotChecksum = errors.New("cache snapshot: checksum mismatch")
	errSnapshotShape    = errors.New("cache snapshot: malformed record")
	errSnapshotSize     = errors.New("cache snapshot: too large")
	errSnapshotBudget   = errors.New("cache snapshot: time budget spent")
)

type snapshotHeader struct {
	compression uint16
	savedAt     time.Time
	fingerprint [32]byte
}

type snapshotRecord struct {
	ttl      time.Duration // lifetime left at saved-at
	lease    time.Duration // lease left at saved-at, noLease when none
	wall     time.Time     // the lease's wall-clock deadline, zero when none
	origTTL  uint32
	cd       bool
	compress bool
	ede      *dns.EDNS0_EDE
	wire     []byte
}

// snapshotWriter streams records into a snapshot.
type snapshotWriter struct {
	file   io.Writer      // the destination, for the trailer
	onDisk *countedWriter // the destination, counting the body's bytes
	lz     *lz4.Writer
	stream io.Writer // the frame, or onDisk for a raw body
	body   io.Writer // stream and the checksum
	sum    hash.Hash32
	n      uint64
	buf    []byte
}

func newSnapshotWriter(w io.Writer, h snapshotHeader) (*snapshotWriter, error) {
	sw := &snapshotWriter{sum: crc32.New(castagnoli)}
	var hdr [snapshotHeaderLen]byte
	copy(hdr[:8], snapshotMagic)
	binary.LittleEndian.PutUint16(hdr[8:], snapshotVersion)
	binary.LittleEndian.PutUint16(hdr[10:], h.compression)
	binary.LittleEndian.PutUint64(hdr[12:], uint64(h.savedAt.UnixNano())) //nolint:gosec // a wall clock instant, bit for bit
	copy(hdr[20:], h.fingerprint[:])
	if _, err := w.Write(hdr[:]); err != nil {
		return nil, err
	}
	_, _ = sw.sum.Write(hdr[:])

	sw.file = w
	sw.onDisk = &countedWriter{w: w}
	sw.stream = sw.onDisk
	if h.compression == snapshotLZ4 {
		sw.lz = lz4.NewWriter(sw.onDisk)
		sw.stream = sw.lz
	}
	sw.body = io.MultiWriter(sw.stream, sw.sum)
	return sw, nil
}

func (sw *snapshotWriter) add(r *snapshotRecord) error {
	b := sw.buf[:0]
	var flags byte
	if r.cd {
		flags |= recFlagCD
	}
	if r.compress {
		flags |= recFlagCompress
	}
	if r.ede != nil {
		flags |= recFlagEDE
	}
	b = append(b, snapshotRecordTag)
	b = binary.LittleEndian.AppendUint64(b, uint64(r.ttl))   //nolint:gosec // a duration, bit for bit
	b = binary.LittleEndian.AppendUint64(b, uint64(r.lease)) //nolint:gosec // noLease round-trips as -1
	var wall int64
	if !r.wall.IsZero() {
		wall = r.wall.UnixNano()
	}
	b = binary.LittleEndian.AppendUint64(b, uint64(wall)) //nolint:gosec // a wall clock instant, bit for bit
	b = binary.LittleEndian.AppendUint32(b, r.origTTL)
	b = append(b, flags)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(r.wire))) //nolint:gosec // bounded by the DNS message size
	if r.ede != nil {
		text := r.ede.ExtraText
		if len(text) > 0xffff {
			text = text[:0xffff]
		}
		b = binary.LittleEndian.AppendUint16(b, r.ede.InfoCode)
		b = binary.LittleEndian.AppendUint16(b, uint16(len(text))) //nolint:gosec // clipped above
		b = append(b, text...)
	}
	b = append(b, r.wire...)
	sw.buf = b
	if _, err := sw.body.Write(b); err != nil {
		return err
	}
	sw.n++
	return nil
}

// finish writes the count and the checksum and closes the frame. The
// checksum goes into the body stream but not into the sum it carries.
func (sw *snapshotWriter) finish() error {
	var end [1 + 8]byte
	end[0] = snapshotEndTag
	binary.LittleEndian.PutUint64(end[1:], sw.n)
	if _, err := sw.body.Write(end[:]); err != nil {
		return err
	}
	var crc [4]byte
	binary.LittleEndian.PutUint32(crc[:], sw.sum.Sum32())
	if _, err := sw.stream.Write(crc[:]); err != nil {
		return err
	}
	if sw.lz != nil {
		if err := sw.lz.Close(); err != nil {
			return err
		}
	}
	var trailer [snapshotTrailerLen]byte
	copy(trailer[:8], snapshotTrailerMagic)
	binary.LittleEndian.PutUint64(trailer[8:], uint64(sw.onDisk.n)) //nolint:gosec // a byte count
	_, err := sw.file.Write(trailer[:])
	return err
}

// countedWriter counts what passes through it.
type countedWriter struct {
	w io.Writer
	n int64
}

func (c *countedWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// limitedReader fails, rather than ending quietly, once more than n bytes
// have been read through it.
type limitedReader struct {
	r   io.Reader
	n   int64
	err error
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, l.err
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}

// scanSnapshot makes one pass over a snapshot. With visit nil it only
// verifies: the header, every record's shape, the count and the checksum,
// and that nothing follows. With visit set it hands over each record in
// turn until visit returns false; the checksum is then not waited for, the
// caller having verified the file in an earlier pass. spent is asked before
// each record, with the number read so far, whether the time budget is gone.
func scanSnapshot(r io.ReadSeeker, spent func(n uint64) bool, visit func(*snapshotRecord) bool) (snapshotHeader, error) {
	var h snapshotHeader
	sum := crc32.New(castagnoli)

	size, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return h, err
	}
	if size > maxSnapshotFileBytes {
		return h, errSnapshotSize
	}
	if size < snapshotHeaderLen+snapshotTrailerLen {
		return h, errSnapshotHeader
	}
	var trailer [snapshotTrailerLen]byte
	if _, err := r.Seek(size-snapshotTrailerLen, io.SeekStart); err != nil {
		return h, err
	}
	if _, err := io.ReadFull(r, trailer[:]); err != nil {
		return h, readErr(err)
	}
	bodyLen := binary.LittleEndian.Uint64(trailer[8:])
	if string(trailer[:8]) != snapshotTrailerMagic ||
		bodyLen != uint64(size-snapshotHeaderLen-snapshotTrailerLen) { //nolint:gosec // size exceeds both lengths, checked above
		return h, errSnapshotShape
	}
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return h, err
	}

	var hdr [snapshotHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return h, errSnapshotHeader
	}
	if string(hdr[:8]) != snapshotMagic || binary.LittleEndian.Uint16(hdr[8:]) != snapshotVersion {
		return h, errSnapshotHeader
	}
	h.compression = binary.LittleEndian.Uint16(hdr[10:])
	h.savedAt = time.Unix(0, int64(binary.LittleEndian.Uint64(hdr[12:]))) //nolint:gosec // written from UnixNano
	copy(h.fingerprint[:], hdr[20:])
	_, _ = sum.Write(hdr[:])

	body := io.LimitReader(r, int64(bodyLen)) //nolint:gosec // bounded by the file size
	switch h.compression {
	case snapshotRaw:
	case snapshotLZ4:
		body = lz4.NewReader(body)
	default:
		return h, errSnapshotHeader
	}
	br := bufio.NewReaderSize(&limitedReader{r: body, n: maxSnapshotStreamBytes, err: errSnapshotSize}, 1<<16)
	in := io.TeeReader(br, sum)

	var (
		fixed [recFixedLen]byte
		n     uint64
		wire  = make([]byte, 0, 512)
	)
	for {
		if spent(n) {
			return h, errSnapshotBudget
		}
		if _, err := io.ReadFull(in, fixed[:1]); err != nil {
			return h, readErr(err)
		}
		if fixed[0] == snapshotEndTag {
			break
		}
		if fixed[0] != snapshotRecordTag {
			return h, errSnapshotShape
		}
		if _, err := io.ReadFull(in, fixed[1:]); err != nil {
			return h, readErr(err)
		}
		rec := snapshotRecord{
			ttl:     time.Duration(binary.LittleEndian.Uint64(fixed[1:])), //nolint:gosec // written from a duration
			lease:   time.Duration(binary.LittleEndian.Uint64(fixed[9:])), //nolint:gosec // written from a duration
			origTTL: binary.LittleEndian.Uint32(fixed[25:]),
		}
		if wall := int64(binary.LittleEndian.Uint64(fixed[17:])); wall != 0 { //nolint:gosec // written from UnixNano
			rec.wall = time.Unix(0, wall)
		}
		flags := fixed[29]
		rec.cd = flags&recFlagCD != 0
		rec.compress = flags&recFlagCompress != 0
		wireLen := binary.LittleEndian.Uint32(fixed[30:])
		if wireLen == 0 || wireLen > maxSnapshotWire || flags&^(recFlagCD|recFlagCompress|recFlagEDE) != 0 {
			return h, errSnapshotShape
		}
		if flags&recFlagEDE != 0 {
			var e [4]byte
			if _, err := io.ReadFull(in, e[:]); err != nil {
				return h, readErr(err)
			}
			text := make([]byte, binary.LittleEndian.Uint16(e[2:]))
			if _, err := io.ReadFull(in, text); err != nil {
				return h, readErr(err)
			}
			rec.ede = &dns.EDNS0_EDE{InfoCode: binary.LittleEndian.Uint16(e[:]), ExtraText: string(text)}
		}
		if cap(wire) < int(wireLen) {
			wire = make([]byte, wireLen)
		}
		wire = wire[:wireLen]
		if _, err := io.ReadFull(in, wire); err != nil {
			return h, readErr(err)
		}
		n++
		if visit != nil {
			rec.wire = wire
			if !visit(&rec) {
				return h, nil
			}
		}
	}

	var count [8]byte
	if _, err := io.ReadFull(in, count[:]); err != nil {
		return h, readErr(err)
	}
	if binary.LittleEndian.Uint64(count[:]) != n {
		return h, errSnapshotShape
	}
	if visit != nil {
		return h, nil
	}
	want := sum.Sum32()
	var crc [4]byte
	if _, err := io.ReadFull(br, crc[:]); err != nil {
		return h, readErr(err)
	}
	if binary.LittleEndian.Uint32(crc[:]) != want {
		return h, errSnapshotChecksum
	}
	// Only a clean end of stream completes the file. Anything else, a byte
	// past the checksum or an LZ4 frame that does not end whole, with its
	// own checksum intact, fails the verification.
	var one [1]byte
	switch _, err := io.ReadFull(br, one[:]); {
	case err == nil:
		return h, errSnapshotShape
	case err != io.EOF: //nolint:errorlint // ReadFull returns io.EOF itself, unwrapped, only for a clean end
		return h, readErr(err)
	}
	return h, nil
}

func readErr(err error) error {
	if errors.Is(err, errSnapshotSize) {
		return errSnapshotSize
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("%w: truncated", errSnapshotShape)
	}
	return err
}
