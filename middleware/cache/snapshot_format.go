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
//
// A record holds what the entry's wire image does not: how much of its
// lifetime and of its delegation lease were left at the saved-at instant,
// its original TTL, its CD bit and compression flag, and its EDE. Integers
// are little endian.
const (
	snapshotMagic   = "SDNSCSNP"
	snapshotVersion = 1

	snapshotRaw = 0
	snapshotLZ4 = 1

	snapshotHeaderLen = 8 + 2 + 2 + 8 + 32

	snapshotRecordTag = 1
	snapshotEndTag    = 0

	// recFixedLen: tag, ttl, lease, origTTL, flags, wire length.
	recFixedLen = 1 + 8 + 8 + 4 + 1 + 4

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
	origTTL  uint32
	cd       bool
	compress bool
	ede      *dns.EDNS0_EDE
	wire     []byte
}

// snapshotWriter streams records into a snapshot.
type snapshotWriter struct {
	lz     *lz4.Writer
	stream io.Writer // the frame, or the file for a raw body
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

	sw.stream = w
	if h.compression == snapshotLZ4 {
		sw.lz = lz4.NewWriter(w)
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
		return sw.lz.Close()
	}
	return nil
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
func scanSnapshot(r io.Reader, spent func(n uint64) bool, visit func(*snapshotRecord) bool) (snapshotHeader, error) {
	var h snapshotHeader
	sum := crc32.New(castagnoli)

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

	var body io.Reader
	switch h.compression {
	case snapshotRaw:
		body = r
	case snapshotLZ4:
		body = lz4.NewReader(r)
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
			origTTL: binary.LittleEndian.Uint32(fixed[17:]),
		}
		flags := fixed[21]
		rec.cd = flags&recFlagCD != 0
		rec.compress = flags&recFlagCompress != 0
		wireLen := binary.LittleEndian.Uint32(fixed[22:])
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
	var one [1]byte
	if k, _ := br.Read(one[:]); k != 0 {
		return h, errSnapshotShape
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
