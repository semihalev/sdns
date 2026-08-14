//go:build zerogate

package zerogate

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// The gate runs only in the dedicated non-race CI job (and by hand):
//
//	go test -tags zerogate -run TestZeroGate ./internal/zerogate/
//
// ZEROGATE_OPS overrides the operation count (default 200k; CI uses 1M).

func TestZeroGate(t *testing.T) {
	flavors := []string{
		FlavorUDP4Specific,
		FlavorTCP,
		FlavorUDP4Wildcard,
		FlavorUDP6Specific,
		FlavorUDP6Wildcard,
	}
	for _, flavor := range flavors {
		t.Run(flavor, func(t *testing.T) {
			if !Gated(flavor) {
				t.Skipf("flavor %s is not gated at stage %s yet", flavor, Stage)
			}
			runGate(t, flavor)
		})
	}
}

// settleWait covers the gap between a client seeing its last reply and
// the server releasing the job that produced it.
const settleWait = 200 * time.Millisecond

func gateOps() int {
	if s := os.Getenv("ZEROGATE_OPS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 200_000
}

func runGate(t *testing.T, flavor string) {
	t.Helper()
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}

	bin := filepath.Join(t.TempDir(), "zerogate-harness")
	build := exec.Command("go", "build", "-o", bin, "./internal/zerogate/harness")
	build.Dir = repoRoot
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("harness build: %v\n%s", err, out)
	}

	var child *harnessProc
	for attempt := 0; attempt < 5 && child == nil; attempt++ {
		bind := pickBind(t, flavor)
		child, err = startHarness(bin, bind)
		if err != nil {
			t.Logf("harness start (bind %s): %v — retrying", bind, err)
		}
	}
	if child == nil {
		t.Fatalf("harness did not start: %v", err)
	}
	defer child.stop(t)

	target := child.clientTarget(flavor)
	warm(t, target)

	ops := gateOps()

	// Connections are established before the window. Accepting a
	// connection is not per-query work, and dialing inside the window
	// charged every accept, goroutine and buffer to the queries that
	// happened to follow.
	var conns []net.Conn
	var counts []int
	if flavor == FlavorTCP {
		conns, counts = prepareTCP(t, target, ops)
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
	}

	m0 := child.mark(t)
	started := time.Now()
	switch flavor {
	case FlavorTCP:
		floodTCPOn(t, conns, counts)
	default:
		floodUDP(t, target, ops)
	}
	// The reply reaching the client precedes the job's release by a few
	// instructions; without this the last of them land in the ambient
	// window instead of the traffic one.
	time.Sleep(settleWait)
	m1 := child.mark(t)
	loadWindow := time.Since(started)

	// An idle window of the same length measures what the process
	// allocates on its own — metric flushers, timers, the runtime — so
	// the verdict below is about the traffic and nothing else.
	a0 := child.mark(t)
	time.Sleep(loadWindow)
	a1 := child.mark(t)
	ambient := a1 - a0

	delta := m1 - m0
	traffic := int64(delta) - int64(ambient)
	t.Logf("stage %s flavor %s: %d ops in %v — window %d mallocs, idle window %d, traffic %+d (slack %d)",
		Stage, flavor, ops, loadWindow.Round(time.Millisecond), delta, ambient, traffic, AmbientSlack)
	if traffic > AmbientSlack {
		t.Fatalf("stage %s flavor %s: %d ops added %d mallocs over an idle window of the same length "+
			"(%.4f/op); the served path must add none",
			Stage, flavor, ops, traffic, float64(traffic)/float64(ops))
	}
}

// pickBind reserves a loopback port for the flavor and releases it for the
// harness to claim. The tiny race is retried by the caller.
func pickBind(t *testing.T, flavor string) string {
	t.Helper()
	host := "127.0.0.1"
	switch flavor {
	case FlavorUDP6Specific, FlavorUDP6Wildcard:
		host = "[::1]"
	}
	l, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	switch flavor {
	case FlavorUDP4Wildcard:
		return fmt.Sprintf("0.0.0.0:%d", port)
	case FlavorUDP6Wildcard:
		return fmt.Sprintf("[::]:%d", port)
	default:
		return fmt.Sprintf("%s:%d", host, port)
	}
}

type harnessProc struct {
	cmd    *exec.Cmd
	stdin  *bufio.Writer
	stdout *bufio.Scanner
	bind   string
}

func startHarness(bin, bind string) (*harnessProc, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "ZEROGATE_BIND="+bind)
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	h := &harnessProc{
		cmd:    cmd,
		stdin:  bufio.NewWriter(in),
		stdout: bufio.NewScanner(out),
		bind:   bind,
	}
	ready := make(chan error, 1)
	go func() {
		for h.stdout.Scan() {
			if strings.HasPrefix(h.stdout.Text(), "READY") {
				ready <- nil
				return
			}
		}
		ready <- fmt.Errorf("harness exited before READY")
	}()
	select {
	case err := <-ready:
		if err != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return nil, err
		}
		return h, nil
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("harness READY timeout")
	}
}

// clientTarget maps a wildcard bind to a concrete client address.
func (h *harnessProc) clientTarget(flavor string) string {
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(h.bind, "["))
	if port == "" {
		if i := strings.LastIndex(h.bind, ":"); i >= 0 {
			port = h.bind[i+1:]
		}
	}
	switch flavor {
	case FlavorUDP6Specific, FlavorUDP6Wildcard:
		return "[::1]:" + port
	default:
		return "127.0.0.1:" + port
	}
}

func (h *harnessProc) mark(t *testing.T) uint64 {
	t.Helper()
	if _, err := h.stdin.WriteString("mark\n"); err != nil {
		t.Fatal(err)
	}
	if err := h.stdin.Flush(); err != nil {
		t.Fatal(err)
	}
	for h.stdout.Scan() {
		line := h.stdout.Text()
		if strings.HasPrefix(line, "MALLOCS ") {
			v, err := strconv.ParseUint(strings.TrimPrefix(line, "MALLOCS "), 10, 64)
			if err != nil {
				t.Fatalf("bad mark line %q: %v", line, err)
			}
			return v
		}
	}
	t.Fatalf("harness closed before mark reply: %v", h.stdout.Err())
	return 0
}

func (h *harnessProc) stop(t *testing.T) {
	t.Helper()
	_, _ = h.stdin.WriteString("quit\n")
	_ = h.stdin.Flush()
	done := make(chan struct{})
	go func() { _ = h.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = h.cmd.Process.Kill()
		<-done
	}
}

func corpusQuery(i int, id uint16) []byte {
	m := new(dns.Msg)
	m.SetQuestion(CorpusName(i), dns.TypeA)
	m.Id = id
	m.RecursionDesired = true
	wire, err := m.Pack()
	if err != nil {
		panic(err)
	}
	return wire
}

// warm resolves the whole corpus twice so measurement windows are hit-only.
func warm(t *testing.T, target string) {
	t.Helper()
	conn, err := net.Dial("udp", target)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	buf := make([]byte, 4096)
	for round := 0; round < 2; round++ {
		for i := 0; i < CorpusSize; i++ {
			ok := false
			for attempt := 0; attempt < 10 && !ok; attempt++ {
				q := corpusQuery(i, uint16(1000+i))
				if _, err := conn.Write(q); err != nil {
					t.Fatal(err)
				}
				_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
				n, err := conn.Read(buf)
				if err != nil {
					continue
				}
				var r dns.Msg
				if r.Unpack(buf[:n]) == nil && r.Id == uint16(1000+i) &&
					r.Rcode == dns.RcodeSuccess && len(r.Answer) > 0 {
					ok = true
				}
			}
			if !ok {
				t.Fatalf("warmup: %s never answered", CorpusName(i))
			}
		}
	}
}

// floodUDP drives ops hit queries through windowed sockets and requires
// every reply back: the gate's accounting identity is replies == ops with
// zero drops — loopback justifies it, and a lost reply must fail the gate
// rather than shrink the denominator.
func floodUDP(t *testing.T, target string, ops int) {
	t.Helper()
	const socks = 16
	const window = 16
	var wg sync.WaitGroup
	perSock := ops / socks

	sockOps := func(s, count int) {
		defer wg.Done()
		conn, err := net.Dial("udp", target)
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		queries := make([][]byte, CorpusSize)
		for i := range queries {
			queries[i] = corpusQuery(i, 0)
		}
		buf := make([]byte, 4096)
		inflight, sent, got := 0, 0, 0
		id := uint16(0)
		for got < count {
			for inflight < window && sent < count {
				q := queries[sent%CorpusSize]
				id++
				binary.BigEndian.PutUint16(q[:2], id)
				if _, err := conn.Write(q); err != nil {
					t.Error(err)
					return
				}
				inflight++
				sent++
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				t.Errorf("sock %d: read after %d replies: %v", s, got, err)
				return
			}
			if n < 12 {
				t.Errorf("sock %d: short reply", s)
				return
			}
			inflight--
			got++
		}
	}

	for s := 0; s < socks; s++ {
		wg.Add(1)
		go sockOps(s, perSock)
	}
	if rem := ops - perSock*socks; rem > 0 {
		wg.Add(1)
		go sockOps(socks, rem)
	}
	wg.Wait()
}

// prepareTCP opens enough connections that the per-connection query
// budget (2048) covers the whole window without a redial, and returns how
// many queries each one carries.
func prepareTCP(t *testing.T, target string, ops int) ([]net.Conn, []int) {
	t.Helper()
	const perConn = 2000 // safety margin under the server's 2048 budget
	n := (ops + perConn - 1) / perConn

	conns := make([]net.Conn, 0, n)
	counts := make([]int, 0, n)
	left := ops
	for range n {
		conn, err := net.Dial("tcp", target)
		if err != nil {
			t.Fatalf("dial %s: %v", target, err)
		}
		conns = append(conns, conn)
		c := perConn
		if left < c {
			c = left
		}
		counts = append(counts, c)
		left -= c
	}
	return conns, counts
}

// floodTCPOn pipelines the prepared connections.
func floodTCPOn(t *testing.T, conns []net.Conn, counts []int) {
	t.Helper()
	const window = 32

	var wg sync.WaitGroup
	for ci := range conns {
		wg.Add(1)
		go func(ci, count int) {
			defer wg.Done()
			conn := conns[ci]
			queries := make([][]byte, CorpusSize)
			for i := range queries {
				w := corpusQuery(i, 0)
				framed := make([]byte, 2+len(w))
				binary.BigEndian.PutUint16(framed, uint16(len(w)))
				copy(framed[2:], w)
				queries[i] = framed
			}
			buf := make([]byte, 65538)
			inflight, sent, got := 0, 0, 0
			id := uint16(0)
			for got < count {
				for inflight < window && sent < count {
					q := queries[sent%CorpusSize]
					id++
					binary.BigEndian.PutUint16(q[2:4], id)
					if _, err := conn.Write(q); err != nil {
						t.Errorf("conn %d write: %v", ci, err)
						return
					}
					inflight++
					sent++
				}
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				if _, err := readFullConn(conn, buf[:2]); err != nil {
					t.Errorf("conn %d read len after %d: %v", ci, got, err)
					return
				}
				l := int(binary.BigEndian.Uint16(buf[:2]))
				if _, err := readFullConn(conn, buf[:l]); err != nil {
					t.Errorf("conn %d read body: %v", ci, err)
					return
				}
				inflight--
				got++
			}
		}(ci, counts[ci])
	}
	wg.Wait()
}

func readFullConn(c net.Conn, b []byte) (int, error) {
	got := 0
	for got < len(b) {
		n, err := c.Read(b[got:])
		if err != nil {
			return got, err
		}
		got += n
	}
	return got, nil
}
