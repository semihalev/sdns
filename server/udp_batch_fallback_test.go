//go:build linux && (amd64 || arm64)

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"golang.org/x/sys/unix"
)

// TestUDPPortableFallbackReplyAddressing pins the recvmmsg-fallback TX
// contract: a socket that fell back to the portable reader stays in the
// batch TX map, but its jobs carry no freshly armed raw sockaddr. The
// send path must route such a job through the direct send — a recycled
// slab still holds the previous client's sockaddr from a batched read,
// and sendmmsg addressed by that stale name answers the wrong client.
func TestUDPPortableFallbackReplyAddressing(t *testing.T) {
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

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	e := newUDPEngine(echo, []*net.UDPConn{server}, false, 1, 8, defaultResourcePlan(1))
	if e.txConns[server] == nil {
		t.Skip("batch TX unavailable on this system")
	}

	victim, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer victim.Close()
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// A recycled slab as a batched read left it: raw sockaddr armed and
	// pointing at the victim.
	poisoned := &udpJob{engine: e}
	victimPort := victim.LocalAddr().(*net.UDPAddr).Port
	var sa [unix.SizeofSockaddrInet4]byte
	sa[0] = byte(unix.AF_INET)
	sa[2], sa[3] = byte(victimPort>>8), byte(victimPort) //nolint:gosec // G115 — a bound UDP port fits 16 bits
	copy(sa[4:8], net.IPv4(127, 0, 0, 1).To4())
	if !poisoned.setRemoteRaw(sa[:]) {
		t.Fatal("victim sockaddr refused")
	}
	copy(poisoned.rawSA[:], sa[:])
	poisoned.rawSALen = uint32(len(sa))
	e.cache.put(poisoned)

	// The fallback shape: workers plus a portable reader on a socket the
	// batch TX map still knows.
	e.workerG.Add(1)
	go e.worker(0)
	e.readers.Add(1)
	go e.reader(server)
	t.Cleanup(func() {
		server.Close() //nolint:gosec // G104 - test socket teardown
		_ = e.stopAndDrain(time.Now().Add(2 * time.Second))
	})

	q := new(dns.Msg)
	q.SetQuestion("fallback.example.com.", dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(raw, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("client never received its reply: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("reply unpack: %v", err)
	}
	if resp.Id != q.Id {
		t.Fatalf("reply id %d, want %d", resp.Id, q.Id)
	}

	// The stale sockaddr must not have been used: the victim hears
	// nothing.
	_ = victim.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	if n, _ := victim.Read(buf); n > 0 {
		t.Fatalf("reply misdirected to the previous client (%d bytes)", n)
	}
}

// TestUDPBatchTXRetirementServesDirect pins the send half of syscall
// degradation: with batch TX retired — the state a permanent sendmmsg
// errno leaves behind — every reply must still reach its client through
// the direct sender. Without retirement, a seccomp policy permitting
// recvmmsg but not sendmmsg was a server that read every query and
// answered none.
func TestUDPBatchTXRetirementServesDirect(t *testing.T) {
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
	if len(l.engine.txConns) == 0 {
		t.Skip("batch TX unavailable on this system")
	}
	l.engine.txRetired.Store(true)
	go func() { _ = l.Serve(ctx) }()
	t.Cleanup(func() {
		sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer scancel()
		_ = l.Shutdown(sctx)
	})

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	q := new(dns.Msg)
	q.SetQuestion("retired.example.com.", dns.TypeA)
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteToUDP(raw, l.pcs[0].LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_ = client.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("no reply with batch TX retired: %v", err)
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf[:n]); err != nil {
		t.Fatalf("reply unpack: %v", err)
	}
	if resp.Id != q.Id {
		t.Fatalf("reply id %d, want %d", resp.Id, q.Id)
	}
}
