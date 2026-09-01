//go:build linux && (amd64 || arm64)

package server

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/sys/unix"
)

// TestUDPBatchSetRemoteRaw pins the raw-sockaddr parse against both
// families, ports and addresses included.
func TestUDPBatchSetRemoteRaw(t *testing.T) {
	j := &udpJob{}

	var sa4 [unix.SizeofSockaddrInet4]byte
	sa4[0] = byte(unix.AF_INET)
	sa4[2], sa4[3] = 0x30, 0x39 // port 12345
	copy(sa4[4:8], []byte{192, 0, 2, 7})
	if !j.setRemoteRaw(sa4[:]) {
		t.Fatal("v4 sockaddr refused")
	}
	if got := j.raddr; got != netip.MustParseAddrPort("192.0.2.7:12345") {
		t.Fatalf("v4 parsed as %v", got)
	}
	if !j.remote.IP.Equal(net.IPv4(192, 0, 2, 7)) || j.remote.Port != 12345 {
		t.Fatalf("v4 classic view %v", j.remote)
	}

	var sa6 [unix.SizeofSockaddrInet6]byte
	sa6[0] = byte(unix.AF_INET6)
	sa6[2], sa6[3] = 0x00, 0x35 // port 53
	sa6[8], sa6[23] = 0x20, 0x01
	if !j.setRemoteRaw(sa6[:]) {
		t.Fatal("v6 sockaddr refused")
	}
	if j.raddr.Port() != 53 || !j.raddr.Addr().Is6() {
		t.Fatalf("v6 parsed as %v", j.raddr)
	}

	if j.setRemoteRaw(sa6[:1]) {
		t.Fatal("truncated sockaddr accepted")
	}
}

// TestUDPBatchEndToEnd floods the batched engine over a real socket and
// expects every query answered through the parked sendmmsg path.
func TestUDPBatchEndToEnd(t *testing.T) {
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

	l := newUDPListener("127.0.0.1:0", echo, time.Second, 4, 64, defaultResourcePlan(1))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := l.Bind(ctx); err != nil {
		t.Fatal(err)
	}
	go func() { _ = l.Serve(ctx) }()
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = l.Shutdown(sctx)
	})

	deadline := time.Now().Add(3 * time.Second)
	for !l.Serving() {
		if time.Now().After(deadline) {
			t.Fatal("listener never started serving")
		}
		time.Sleep(5 * time.Millisecond)
	}
	l.mu.Lock()
	senders := len(l.engine.txConns)
	addr := l.pcs[0].LocalAddr().String()
	l.mu.Unlock()
	if senders == 0 {
		t.Fatal("batched send handles not armed on linux")
	}

	const clients, perClient = 8, 25
	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for c := range clients {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			conn, err := net.Dial("udp", addr)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			buf := make([]byte, 4096)
			for i := range perClient {
				q := new(dns.Msg)
				q.SetQuestion(dns.Fqdn("batch.zero.test."), dns.TypeA)
				q.Id = uint16(c*perClient + i + 1) //nolint:gosec // bounded test values
				raw, _ := q.Pack()
				_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
				if _, err := conn.Write(raw); err != nil {
					errs <- err
					return
				}
				n, err := conn.Read(buf)
				if err != nil {
					errs <- err
					return
				}
				resp := new(dns.Msg)
				if err := resp.Unpack(buf[:n]); err != nil {
					errs <- err
					return
				}
				if resp.Id != q.Id || !resp.Response {
					errs <- errBadReply
					return
				}
			}
		}(c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("batched exchange failed: %v", err)
	}
}

var errBadReply = &net.AddrError{Err: "bad reply", Addr: "batch"}

// TestUDPBatchReaderWakesOnShutdown pins the exhausted reader's exit
// against the drain deadline.
//
// With the lease cap reached the reader gets no slab, so it sheds: it
// keeps consuming the socket into scratch memory, counting the loss.
// The only thing that ends a shedding reader is its socket, which is
// exactly what shutdown provides through the expired read deadline. A
// reader that waited for a slab instead would be waiting on workers
// releasing what they hold, and a worker stuck past the drain deadline
// would hold the whole shutdown hostage with it.
func TestUDPBatchReaderWakesOnShutdown(t *testing.T) {
	handler := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		return true
	})

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := newUDPEngine(handler, []*net.UDPConn{pc}, false, 1, 1, defaultResourcePlan(1))

	// The cap is exhausted before the reader exists, the state a burst
	// of slow queries leaves behind, with every slab held by a request
	// that is not coming back before the deadline.
	e.leased.Store(e.slabCap)
	if !e.startBatched() {
		_ = pc.Close()
		t.Skip("batched receive unavailable on this kernel")
	}

	// Admission stop, exactly as the listener does it: the expired
	// deadline wakes the reader's shed read, and nothing else has to.
	if err := pc.SetReadDeadline(time.Now()); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- e.stopAndDrain(time.Now().Add(3 * time.Second)) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("drain returned %v", err)
		}
	case <-time.After(6 * time.Second):
		t.Fatal("drain never returned: the exhausted batched reader had no " +
			"way out of its shed loop")
	}
	_ = pc.Close()
	e.leased.Store(0)
}
