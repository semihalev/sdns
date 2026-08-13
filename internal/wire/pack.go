package wire

import (
	"encoding/binary"
	"sync"

	"github.com/miekg/dns"
)

// TryPack encodes msg into wire format inside pooled storage and hands the
// bytes to consume. It exists because the library's Pack builds a compression
// dictionary and sizes an output array for every message it encodes; for a
// server that answers a query per packet, that was a map and an array per
// answer. Here both come from a pool, and the caller never touches either.
//
// The contract, in order of importance:
//
//   - The bytes handed to consume are exactly what dns.Msg.Pack would have
//     produced. Where this cannot be guaranteed, TryPack does not try: it
//     reports handled=false, no bytes are produced, and the caller uses the
//     library path it was already using.
//   - msg is not modified — not its header, not its records, not its OPT.
//     This is deliberately stronger than the library, which writes the
//     extended rcode into the caller's OPT and, through the public PackRR,
//     the computed Rdlength into the caller's record headers. Both writes
//     land in pooled shims here instead.
//   - The slice given to consume is valid only for the duration of the call.
//     A consumer that needs the bytes afterwards copies them; PackClone is
//     that, prepackaged.
//
// handled=true with a non-nil error is the consumer's error, reported after
// bytes may already have left the process — the caller must not fall back and
// write a second response.
func TryPack(msg *dns.Msg, consume func([]byte) error) (handled bool, err error) {
	if msg == nil || msg.Rcode < 0 || msg.Rcode > 0xFFF {
		return false, nil
	}
	// The extended rcode travels in the OPT record. With no OPT to carry it,
	// the library errors; that path is left to the library so the error is
	// its own.
	opt := msg.IsEdns0()
	if opt == nil && msg.Rcode > 0xF {
		return false, nil
	}

	state := packStatePool.Get().(*packState)
	defer state.release()

	compress := msg.Compress && msgIsCompressible(msg)
	var compression map[string]int
	if compress {
		if state.compression == nil {
			state.compression = make(map[string]int, maxPooledCompressionEntries)
		}
		compression = state.compression
	}

	off, ok := state.packInto(msg, opt, compression, compress)
	if !ok {
		return false, nil
	}
	return true, consume(state.buf[:off])
}

// PackClone packs msg and returns an exact-size copy the caller owns. It is
// for the callsites that keep the bytes — a cache entry, an async queue —
// where a borrowed buffer must never travel. The library path is the
// fallback, trimmed to size the same way, so the caller sees one shape.
func PackClone(msg *dns.Msg) ([]byte, error) {
	var owned []byte
	handled, err := TryPack(msg, func(body []byte) error {
		owned = make([]byte, len(body))
		copy(owned, body)
		return nil
	})
	if handled {
		return owned, err
	}

	packed, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	// Pack sizes its backing array for the uncompressed length and returns
	// the compressed prefix; half the capacity can be dead weight on a
	// compressible message, and the callers of this keep what they get.
	owned = make([]byte, len(packed))
	copy(owned, packed)
	return owned, nil
}

// packState is everything one pack borrows, under a single pool pointer: the
// output buffer, the compression dictionary, the record shim that absorbs the
// Rdlength write, and the OPT copy that carries the extended rcode.
type packState struct {
	compression map[string]int
	rr          rrView
	opt         dns.OPT
	buf         [packBufferSize]byte
}

// packInto encodes msg into state.buf, returning the length and whether the
// custom path accounted for everything it saw. Anything it did not — a record
// kind with its own packing protocol, a message that does not fit, an
// encoding error — is a fallback, never a guess.
func (state *packState) packInto(
	msg *dns.Msg,
	opt *dns.OPT,
	compression map[string]int,
	compress bool,
) (int, bool) {
	out := state.buf[:]

	binary.BigEndian.PutUint16(out[0:2], msg.Id)
	binary.BigEndian.PutUint16(out[2:4], msgBits(msg))
	binary.BigEndian.PutUint16(out[4:6], uint16(len(msg.Question))) //nolint:gosec // the library packs these counts with the same truncation
	binary.BigEndian.PutUint16(out[6:8], uint16(len(msg.Answer)))   //nolint:gosec // see above
	binary.BigEndian.PutUint16(out[8:10], uint16(len(msg.Ns)))      //nolint:gosec // see above
	binary.BigEndian.PutUint16(out[10:12], uint16(len(msg.Extra)))  //nolint:gosec // see above

	off := headerLen
	for i := range msg.Question {
		var err error
		off, err = packQuestion(&msg.Question[i], out, off, compression, compress)
		if err != nil {
			return 0, false
		}
	}

	for _, section := range [3][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr == nil {
				return 0, false
			}
			// PrivateRR packs through a caller-registered protocol whose
			// sizing pass the library runs and this path does not. Its
			// side-effect order is that caller's contract, not ours to
			// reorder.
			if _, ok := rr.(*dns.PrivateRR); ok {
				return 0, false
			}
			// At off == len(out) there is no room even for a header. On the
			// current library PackRR's own per-field bounds checks refuse
			// this too — the guard is defense in depth, so a change in those
			// checks cannot turn an exactly-full buffer into a record packed
			// over the payload's tail.
			if off >= len(out) {
				return 0, false
			}

			target := rr
			if o, ok := rr.(*dns.OPT); ok && o == opt {
				// The library writes the extended rcode into the caller's
				// OPT and packs the mutated record. Same bytes, different
				// home: a copy carries the rewritten TTL, and the caller's
				// record keeps its own. The write is unconditional in the
				// library — a low rcode clears stale extended bits — so it
				// is unconditional here.
				state.opt = *o
				state.opt.Hdr.Ttl = o.Hdr.Ttl&0x00FFFFFF |
					uint32(msg.Rcode>>4)<<24 //nolint:gosec // rcode is range-checked in TryPack
				target = &state.opt
			}

			// The shim is what PackRR writes the computed Rdlength into;
			// the record itself stays as the caller built it.
			state.rr.RR = target
			state.rr.hdr = *target.Header()
			off1, err := dns.PackRR(&state.rr, out, off, compression, compress)
			state.rr.RR = nil
			if err != nil || off1 <= off || off1 > len(out) {
				return 0, false
			}
			off = off1
		}
	}
	return off, true
}

// rrView is the record shim: it presents a copy of the record's header while
// delegating everything else to the record itself. The exported PackRR ends a
// successful pack by writing the computed Rdlength through Header(); routed
// here, that write lands in hdr and the caller's record is never touched. The
// wire bytes come from the embedded record's own packing, which reads its own
// fields — identical to the copy by construction.
type rrView struct {
	dns.RR
	hdr dns.RR_Header
}

func (v *rrView) Header() *dns.RR_Header { return &v.hdr }

// packQuestion writes one question. dns.Question.pack is unexported, but it
// is a name followed by two fixed fields.
func packQuestion(
	q *dns.Question,
	out []byte,
	off int,
	compression map[string]int,
	compress bool,
) (int, error) {
	off, err := dns.PackDomainName(q.Name, out, off, compression, compress)
	if err != nil {
		return 0, err
	}
	if off+4 > len(out) {
		return 0, dns.ErrBuf
	}
	binary.BigEndian.PutUint16(out[off:off+2], q.Qtype)
	binary.BigEndian.PutUint16(out[off+2:off+4], q.Qclass)
	return off + 4, nil
}

// msgBits assembles the header's second word. dns.Msg carries the flags as
// fields and the library rebuilds this word on every pack.
func msgBits(msg *dns.Msg) uint16 {
	bits := uint16(msg.Opcode)<<11 | uint16(msg.Rcode&0xF) //nolint:gosec // both are masked to their field widths
	for _, flag := range [...]struct {
		set bool
		bit uint16
	}{
		{msg.Response, 1 << 15},
		{msg.Authoritative, 1 << 10},
		{msg.Truncated, 1 << 9},
		{msg.RecursionDesired, 1 << 8},
		{msg.RecursionAvailable, 1 << 7},
		{msg.Zero, 1 << 6},
		{msg.AuthenticatedData, 1 << 5},
		{msg.CheckingDisabled, 1 << 4},
	} {
		if flag.set {
			bits |= flag.bit
		}
	}
	return bits
}

// msgIsCompressible mirrors dns.Msg.isCompressible, which is unexported: a
// message with a single question and no records has no name to point back to.
//
// The question count is part of it. A message with more than one question does
// not occur in practice, and leaving that clause out is why an earlier version
// packed one uncompressed while the library compressed it — a difference no
// hand-written case would have found.
func msgIsCompressible(msg *dns.Msg) bool {
	return len(msg.Question) > 1 || len(msg.Answer) > 0 ||
		len(msg.Ns) > 0 || len(msg.Extra) > 0
}

const headerLen = 12

// packBufferSize is what a pooled buffer holds: the largest message this path
// packs without falling back. The field profile's pack-buffer size classes
// top out well under this; a message that needs more takes the library path,
// which sizes for it, rather than a second allocation here.
const packBufferSize = 4096

// maxPooledCompressionEntries bounds what a pooled dictionary may keep, so
// one unusually name-heavy message does not set the resting size of every
// dictionary after it.
const maxPooledCompressionEntries = 64

var packStatePool = sync.Pool{
	New: func() any { return new(packState) },
}

// release returns the state to the pool with nothing of the message left in
// it. The shim held the last record packed, the OPT copy holds the caller's
// option list, and the dictionary's keys are the message's owner names — any
// of them still referenced from the pool would keep the whole message alive.
func (state *packState) release() {
	state.rr.RR = nil
	state.rr.hdr = dns.RR_Header{}
	state.opt = dns.OPT{}
	if state.compression != nil {
		if len(state.compression) > maxPooledCompressionEntries {
			state.compression = nil
		} else {
			clear(state.compression)
		}
	}
	packStatePool.Put(state)
}
