package server

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
)

// scriptedConn replays a preloaded byte stream to the engine and keeps
// what the engine writes back. Reads come from memory, so a pipelined
// burst is guaranteed to reach the fill buffer in one read — which is
// exactly the state the class swap is about, and which a real socket
// would only usually produce.
type scriptedConn struct {
	in     *bytes.Reader
	closed chan struct{}
	once   sync.Once

	mu  sync.Mutex
	out bytes.Buffer
}

func newScriptedConn(script []byte) *scriptedConn {
	return &scriptedConn{in: bytes.NewReader(script), closed: make(chan struct{})}
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.in.Len() > 0 {
		return c.in.Read(p)
	}
	// The script is spent: the connection is simply a client with nothing
	// more to say, until the test hangs up.
	<-c.closed
	return 0, io.EOF
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}

func (c *scriptedConn) wroteAnything() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Len() > 0
}

func (c *scriptedConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func (c *scriptedConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func (c *scriptedConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 5353}
}

func (c *scriptedConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(time.Time) error { return nil }

// framed prefixes a payload for the stream transport.
func framed(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	binary.BigEndian.PutUint16(out, uint16(len(payload))) //nolint:gosec // fixture payloads are small
	copy(out[2:], payload)
	return out
}

// paddedQuery builds a query large enough to need the large class.
func paddedQuery(t *testing.T, name string, pad int) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(dns.MaxMsgSize)
	opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, pad)})
	m.Extra = append(m.Extra, opt)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= tcpSmallFrame {
		t.Fatalf("padded query is %d bytes, not large-class", len(raw))
	}
	return raw
}

func plainQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// TestTCPLargeSlabReturnsWhenTheBurstShrinks pins the class swap in the
// direction that keeps the server up.
//
// The large ring is deliberately shallow — large frames are rare, and
// sizing the ring for them would make the resident set about the rarest
// case. That only holds if a large slab is given back as soon as the
// frames stop being large. A connection that met one 2-4KB frame and then
// went back to ordinary queries used to hold its large slab for the rest
// of the burst, so defaultTCPLargeJobs busy connections owned the class
// outright and the next client to announce a large frame waited its whole
// budget and was dropped — with a ring nobody needed.
func TestTCPLargeSlabReturnsWhenTheBurstShrinks(t *testing.T) {
	hold := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(hold) }) }

	entered := make(chan struct{}, defaultTCPLargeJobs)
	handler := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		r := new(dns.Msg)
		if err := r.Unpack(raw); err != nil {
			return false
		}
		if r.Question[0].Name == "hold." {
			// Parked here, this connection is mid-burst: it has served a
			// large frame and is serving a small one, holding whatever slab
			// the swap left it with.
			entered <- struct{}{}
			<-hold
		}
		m := new(dns.Msg)
		m.SetReply(r)
		return w.WriteMsg(m) == nil
	})

	e := newTCPEngine(handler, "tcp", 64, defaultResourcePlan(1))

	burst := append(framed(paddedQuery(t, "big.", 2500)), framed(plainQuery(t, "hold."))...)
	conns := make([]*scriptedConn, cap(e.largeTokens))
	for i := range conns {
		conns[i] = newScriptedConn(burst)
		e.register(conns[i])
		go e.serveConn(conns[i])
	}
	late := newScriptedConn(framed(paddedQuery(t, "late.", 2500)))
	t.Cleanup(func() {
		release()
		for _, c := range conns {
			_ = c.Close()
		}
		_ = late.Close()
	})

	for range conns {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatal("connections never reached the small frame of their burst")
		}
	}

	if got, want := len(e.largeTokens), cap(e.largeTokens); got != want {
		t.Fatalf("%d of %d large tokens free while every connection is on a small "+
			"frame; a burst that shrinks must hand the large slab back, or this "+
			"many connections own the class for as long as they stay busy", got, want)
	}

	// And the class is usable, not merely accounted for: a large frame
	// arriving now is served instead of waiting out its budget.
	e.register(late)
	go e.serveConn(late)
	deadline := time.Now().Add(tcpQueryWait)
	for !late.wroteAnything() && time.Now().Before(deadline) {
		time.Sleep(2 * time.Millisecond)
	}
	if !late.wroteAnything() {
		t.Fatal("a large frame went unanswered while the large ring was full")
	}

	release()
	for _, c := range conns {
		_ = c.Close()
	}
	_ = late.Close()
	e.wg.Wait()
}
