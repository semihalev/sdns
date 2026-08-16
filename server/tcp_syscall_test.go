package server

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// countingConn is a net.Conn whose reads come from a script and whose
// writes are counted. It exists to make the burst path's syscall shape
// observable: throughput on a shared machine is too noisy to gate on,
// but the property that produces it — one read and one write per burst,
// however many queries the burst carries — is exact.
type countingConn struct {
	mu      sync.Mutex
	script  [][]byte // successive read payloads
	pos     int
	reads   int
	writes  int
	written []byte
	closed  chan struct{}
	once    sync.Once
}

func newCountingConn(script ...[]byte) *countingConn {
	return &countingConn{script: script, closed: make(chan struct{})}
}

func (c *countingConn) Read(b []byte) (int, error) {
	c.mu.Lock()
	if c.pos >= len(c.script) {
		c.mu.Unlock()
		// The script is exhausted: the connection goes quiet, exactly as a
		// client that has nothing more to ask. The engine must have
		// flushed before reaching here.
		<-c.closed
		return 0, io.EOF
	}
	chunk := c.script[c.pos]
	c.pos++
	c.reads++
	n := copy(b, chunk)
	c.mu.Unlock()
	if n < len(chunk) {
		return n, io.ErrShortBuffer
	}
	return n, nil
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.written = append(c.written, b...)
	return len(b), nil
}

func (c *countingConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *countingConn) counts() (reads, writes int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reads, c.writes
}

func (c *countingConn) replies() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.written...)
}

func (c *countingConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (c *countingConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(203, 0, 113, 60), Port: 4242}
}

func (c *countingConn) SetDeadline(time.Time) error      { return nil }
func (c *countingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *countingConn) SetWriteDeadline(time.Time) error { return nil }

// TestTCPBurstCostsOneWrite is the executable non-regression gate for the
// stream path's syscall shape. A pipelined burst answered one write at a
// time is what the profile found the TCP engine spending its time on, and
// what a throughput number would only tell us about indirectly and
// noisily. The shape itself is deterministic, so it is what gets pinned:
// one burst in, one write out.
func TestTCPBurstCostsOneWrite(t *testing.T) {
	const burst = 40

	var frames []byte
	for i := range burst {
		q := new(dns.Msg)
		q.SetQuestion(dns.Fqdn("s"+string(rune('a'+i%26))+".burst.test"), dns.TypeA)
		q.Id = uint16(700 + i) //nolint:gosec // bounded test values
		raw, err := q.Pack()
		if err != nil {
			t.Fatal(err)
		}
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(raw))) //nolint:gosec // bounded
		frames = append(frames, prefix[:]...)
		frames = append(frames, raw...)
	}

	echo := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		m := new(dns.Msg)
		m.SetReply(r)
		_ = w.WriteMsg(m)
		return true
	})

	e := newTCPEngine(echo, "tcp", 8, defaultResourcePlan(1))
	conn := newCountingConn(frames)

	done := make(chan struct{})
	go func() {
		defer close(done)
		e.register(conn)
		e.serveConn(conn)
	}()

	// The engine serves the burst, flushes, and blocks on the quiet
	// connection; releasing it then ends the loop.
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, writes := conn.counts(); writes > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no reply was ever written")
		}
		time.Sleep(2 * time.Millisecond)
	}
	_ = conn.Close()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection loop did not exit")
	}

	reads, writes := conn.counts()
	if writes != 1 {
		t.Fatalf("a %d-query burst cost %d writes; the burst must leave in one",
			burst, writes)
	}
	if reads != 1 {
		t.Fatalf("a %d-query burst cost %d reads; the burst must arrive in one",
			burst, reads)
	}

	// Every query is answered, in order, in that single write.
	replies := conn.replies()
	off := 0
	for i := range burst {
		if off+2 > len(replies) {
			t.Fatalf("reply %d missing from the flushed burst", i)
		}
		n := int(binary.BigEndian.Uint16(replies[off : off+2]))
		off += 2
		if off+n > len(replies) {
			t.Fatalf("reply %d truncated in the flushed burst", i)
		}
		resp := new(dns.Msg)
		if err := resp.Unpack(replies[off : off+n]); err != nil {
			t.Fatalf("reply %d: %v", i, err)
		}
		if resp.Id != uint16(700+i) { //nolint:gosec // bounded
			t.Fatalf("reply %d has id %d", i, resp.Id)
		}
		off += n
	}
	if off != len(replies) {
		t.Fatalf("%d trailing bytes after the burst's replies", len(replies)-off)
	}
}
