package dnsclient

import (
	"errors"
	"io"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// fakePacketConn is a net.Conn that also satisfies net.PacketConn (so
// (*Conn).Read takes its UDP branch) and hands back a fixed datagram.
// readN lets a test report fewer bytes than it copied into the caller's
// buffer, simulating a pooled buffer whose tail still holds stale data.
type fakePacketConn struct {
	net.PacketConn // nil — only the promoted method set is needed for the type assertion
	readData       []byte
	readN          int
}

func (f *fakePacketConn) Read(p []byte) (int, error) {
	copy(p, f.readData)
	return f.readN, nil
}
func (f *fakePacketConn) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakePacketConn) RemoteAddr() net.Addr        { return nil }

func TestReadMsg_ShortRead(t *testing.T) {
	co := &Conn{Conn: &fakePacketConn{readData: []byte{1, 2, 3, 4}, readN: 4}, UDPSize: 512}
	_, err := co.ReadMsg()
	if err != dns.ErrShortRead {
		t.Fatalf("expected ErrShortRead, got %v", err)
	}
}

// TestReadMsg_UnpacksOnlyBytesRead exercises the p[:n] fix: the pooled
// buffer holds a complete, valid message, but the connection reports a
// short read that cuts off the final rdata bytes. ReadMsg must unpack
// only the bytes actually received (and so reject the truncated record)
// rather than reading the stale tail of the buffer as valid rdata.
func TestReadMsg_UnpacksOnlyBytesRead(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeTXT)
	msg.Response = true
	rr, err := dns.NewRR("example.com. 60 IN TXT \"this-is-a-long-txt-record-used-to-pad-the-rdata\"")
	if err != nil {
		t.Fatalf("build TXT RR: %v", err)
	}
	msg.Answer = []dns.RR{rr}

	full, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}

	// The datagram is three bytes short of the full message — those
	// bytes land inside the TXT rdata. With the fix, only full[:n] is
	// unpacked and the truncated record is rejected. Without it, the
	// trailing bytes (still present in the buffer) would be parsed as
	// valid rdata.
	n := len(full) - 3
	co := &Conn{Conn: &fakePacketConn{readData: full, readN: n}, UDPSize: 4096}

	if _, err := co.ReadMsg(); err == nil {
		t.Fatal("expected an unpack error from the truncated datagram, got nil")
	}
}

// fakeSeqPacketConn satisfies net.PacketConn and returns a queued
// sequence of datagrams on successive Reads, so a test can feed a stray
// mismatched-ID packet ahead of the real response.
type fakeSeqPacketConn struct {
	net.PacketConn
	datagrams [][]byte
	idx       int
}

func (f *fakeSeqPacketConn) Read(p []byte) (int, error) {
	if f.idx >= len(f.datagrams) {
		return 0, io.EOF // no more datagrams; stands in for a read deadline
	}
	d := f.datagrams[f.idx]
	f.idx++
	return copy(p, d), nil
}
func (f *fakeSeqPacketConn) Write(p []byte) (int, error) { return len(p), nil }
func (f *fakeSeqPacketConn) RemoteAddr() net.Addr        { return nil }

// TestExchange_UDP_SkipsMismatchedID is the regression guard for the
// forwarder/failover path: a connected UDP socket may surface a stray
// datagram (a late reply to a timed-out query, or a spoof) before the
// real answer. Exchange must skip the mismatched ID and keep reading,
// matching miekg/dns.Client, rather than failing the whole exchange on
// the first stray packet.
func TestExchange_UDP_SkipsMismatchedID(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 0x1234

	stray := new(dns.Msg)
	stray.SetQuestion("example.com.", dns.TypeA)
	stray.Response = true
	stray.Id = 0x9999 // mismatched — a reply to some earlier query
	strayWire, err := stray.Pack()
	if err != nil {
		t.Fatalf("pack stray: %v", err)
	}

	real := new(dns.Msg)
	real.SetQuestion("example.com.", dns.TypeA)
	real.Response = true
	real.Id = 0x1234 // matches the request
	rr, _ := dns.NewRR("example.com. 60 IN A 93.184.216.34")
	real.Answer = []dns.RR{rr}
	realWire, err := real.Pack()
	if err != nil {
		t.Fatalf("pack real: %v", err)
	}

	co := &Conn{
		Conn:    &fakeSeqPacketConn{datagrams: [][]byte{strayWire, realWire}},
		UDPSize: 512,
	}
	resp, _, err := co.Exchange(req)
	if err != nil {
		t.Fatalf("expected the stray packet to be skipped, got error: %v", err)
	}
	if resp.Id != req.Id {
		t.Fatalf("expected matching response id %#x, got %#x", req.Id, resp.Id)
	}
	if len(resp.Answer) != 1 {
		t.Fatalf("expected the real answer, got %d records", len(resp.Answer))
	}
}

// fakeStreamConn is a net.Conn (not a net.PacketConn, so (*Conn).ReadMsg
// takes its stream branch) that replays a fixed byte script across Reads
// and then reports EOF — letting a test deliver a length prefix followed
// by a short body.
type fakeStreamConn struct {
	net.Conn
	data []byte
	pos  int
}

func (f *fakeStreamConn) Read(p []byte) (int, error) {
	if f.pos >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.pos:])
	f.pos += n
	return n, nil
}

// TestReadMsg_TCPPartialRead_PropagatesError guards against the shadowed-
// err regression: the 2-byte length prefix promises 100 bytes but the
// stream delivers only 50 then EOF, so io.ReadFull returns
// ErrUnexpectedEOF. ReadMsg must propagate that read error instead of
// swallowing it and falling through to a short-read/unpack error.
func TestReadMsg_TCPPartialRead_PropagatesError(t *testing.T) {
	data := append([]byte{0x00, 0x64}, make([]byte, 50)...) // length=100, body=50
	co := &Conn{Conn: &fakeStreamConn{data: data}}

	_, err := co.ReadMsg()
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("expected ErrUnexpectedEOF to propagate, got %v", err)
	}
}

// FuzzReadMsg feeds arbitrary bytes through the UDP read path to ensure
// the framing never panics regardless of the wire contents.
func FuzzReadMsg(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	seed := new(dns.Msg)
	seed.SetQuestion("example.com.", dns.TypeA)
	if b, err := seed.Pack(); err == nil {
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		size := len(data)
		if size == 0 || size > 65535 {
			size = 512
		}
		co := &Conn{Conn: &fakePacketConn{readData: data, readN: len(data)}, UDPSize: uint16(size)} //nolint:gosec // bounded above
		_, _ = co.ReadMsg()
	})
}
