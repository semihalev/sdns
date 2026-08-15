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
	small, large := measure(t, flavor, gateOps(), nil)

	// Verdict one, exact: the server allocated nothing while serving.
	// Attribution is what makes an exact zero meaningful — a process-wide
	// count cannot tell a query's allocation from a timer's, so it can
	// only ever be compared against slack, while a stack either passes
	// through the engines or it does not.
	for _, w := range []struct {
		name string
		win  window
	}{{"1x", small}, {"2x", large}} {
		t.Logf("stage %s flavor %s %s: %d ops in %v — %d objects allocated by the server "+
			"while serving, %d unclassifiable, %d elsewhere in the server "+
			"(%d of them scheduler parking), %d mallocs process-wide (measurement included)",
			Stage, flavor, w.name, w.win.ops, w.win.elapsed.Round(time.Millisecond),
			w.win.served, w.win.unknown, w.win.other, w.win.parked, w.win.mallocs)
		if err := exactVerdict(w.win); err != nil {
			for _, line := range w.win.offenders {
				t.Log("  ", line)
			}
			t.Fatalf("stage %s flavor %s: %v", Stage, flavor, err)
		}
	}

	if os.Getenv("ZEROGATE_ALL_SITES") != "" {
		for i, line := range large.offenders {
			if i == 12 {
				break
			}
			t.Log("  2x site:", line)
		}
	}

	// Verdict two, ops-relative: more traffic must not move what the rest
	// of the server allocates. Serving hands work to goroutines whose
	// stacks carry no engine frame — a prefetch refresh, a metric flush, a
	// log line — and attribution alone would not see them. Their constant
	// background is the same in both windows and cancels in the
	// difference; what survives is per-query, wherever it lives.
	growth := large.other - small.other
	extra := large.ops - small.ops
	t.Logf("stage %s flavor %s: %d extra queries moved the rest of the server by %+d (%.6f/op, bound %d)",
		Stage, flavor, extra, growth, float64(growth)/float64(extra), ScalingSlack)
	if err := scalingVerdict(small, large); err != nil {
		t.Fatalf("stage %s flavor %s: %v", Stage, flavor, err)
	}
}

// exactVerdict is the hard one: the server's own code allocated nothing
// on a serving goroutine, and nothing was too deep to classify.
func exactVerdict(w window) error {
	if w.served != 0 {
		return fmt.Errorf("%d objects allocated while serving %d queries; "+
			"the served path must allocate none", w.served, w.ops)
	}
	if w.unknown != 0 {
		return fmt.Errorf("%d objects allocated on stacks too deep to classify over "+
			"%d queries; an allocation that cannot be shown to be off the serving "+
			"path counts as on it", w.unknown, w.ops)
	}
	return nil
}

// scalingVerdict is the ops-relative one: nothing off the serving stacks
// grows with the traffic.
func scalingVerdict(small, large window) error {
	growth := large.other - small.other
	extra := large.ops - small.ops
	if growth > ScalingSlack {
		return fmt.Errorf("%d extra queries cost %d extra objects off the serving "+
			"stacks (%.6f/op); something the queries reach scales with traffic",
			extra, growth, float64(growth)/float64(extra))
	}
	return nil
}

// measure runs the harness through a warm-up window and two measured
// ones, the second carrying twice the traffic of the first.
func measure(t *testing.T, flavor string, ops int, env []string) (window, window) {
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
		child, err = startHarness(bin, bind, env)
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

	// Two windows, the second carrying twice the traffic of the first.
	// One window can only ever be compared against a tolerance, and a
	// tolerance is an allowance for allocating; two windows separate the
	// process's constant background from anything that scales with
	// queries, because only the latter doubles.
	child.quiesce(t)
	child.markBoth(t) // opens the first window; its own counts are the baseline

	// A discarded window first. The claim is about serving, and serving
	// steadily: the first packet through a path also builds the itab the
	// runtime looks a method up in, grows a worker's stack, and touches
	// each slab for the first time. Those are properties of starting, not
	// of a query, and they are one-time by construction — a per-query cost
	// would still be there in the windows that follow, which is what makes
	// discarding this one safe rather than convenient.
	runFlood(t, child, flavor, target, warmupOps(ops))

	// The pair is ops/2 and ops rather than ops and 2*ops: a TCP window
	// cannot ask for more queries than the server's connection cap times
	// its per-connection budget, and the larger of the two is what has to
	// fit.
	small := runFlood(t, child, flavor, target, ops/2)
	large := runFlood(t, child, flavor, target, ops)
	return small, large
}

// TestZeroGateCatchesInjectedAllocations tests the gate rather than the
// server. A verdict nobody has ever seen fail is a verdict nobody knows
// the shape of, and both of these shapes were chosen because they are the
// ones attribution is weakest against.
//
// It runs at a fraction of the gate's traffic: the injected allocations
// are per query, so they are unmissable long before a million of them.
func TestZeroGateCatchesInjectedAllocations(t *testing.T) {
	const ops = 20_000

	t.Run("deep serving allocation", func(t *testing.T) {
		// Allocated on the serving goroutine, but far enough down the
		// stack that the engine's frames fall off the end of a profile
		// record. Attribution cannot see what it is; the exact verdict
		// must still refuse it.
		small, large := measure(t, FlavorUDP4Specific, ops, []string{"ZEROGATE_INJECT=deep"})
		t.Logf("caught as: served %d/%d, unclassifiable %d/%d over %d/%d queries",
			small.served, large.served, small.unknown, large.unknown, small.ops, large.ops)
		if exactVerdict(small) == nil && exactVerdict(large) == nil {
			t.Fatalf("a deep serving allocation passed the exact verdict "+
				"(served %d/%d, unclassifiable %d/%d)",
				small.served, large.served, small.unknown, large.unknown)
		}
	})

	t.Run("allocation handed to another goroutine", func(t *testing.T) {
		// Nothing allocates on the serving stack: the handler passes a
		// token to a goroutine that was already running. Attribution is
		// blind to this by construction, which is the whole reason the
		// second verdict exists.
		small, large := measure(t, FlavorUDP4Specific, ops, []string{"ZEROGATE_INJECT=async"})
		t.Logf("caught as: %d → %d objects off the serving stacks over %d → %d queries "+
			"(exact verdict saw served %d/%d)",
			small.other, large.other, small.ops, large.ops, small.served, large.served)
		if err := scalingVerdict(small, large); err == nil {
			t.Fatalf("an allocation handed to another goroutine passed the scaling "+
				"verdict (other %d → %d over %d → %d queries)",
				small.other, large.other, small.ops, large.ops)
		}
	})
}

// warmupOps sizes the discarded window: enough traffic for every slab in
// every ring to have been served at least once, and cheap next to the
// measured ones.
func warmupOps(ops int) int {
	if ops < 25_000 {
		return ops
	}
	return 25_000
}

// window is one measured traffic window.
type window struct {
	ops       int
	mallocs   uint64
	served    int64
	other     int64
	parked    int64
	unknown   int64
	elapsed   time.Duration
	offenders []string
}

// runFlood measures one window: traffic, then the server's own completion
// barrier, then the mark. The barrier replaces waiting a fixed time for
// the last slabs to come home — a sleep either wastes the difference or,
// on a slow machine, closes the window while jobs are still being
// released, which charges their work to whatever window comes next.
func runFlood(t *testing.T, child *harnessProc, flavor, target string, ops int) window {
	t.Helper()

	// A TCP window brings its own connections, and they are opened before
	// it starts: accepting is not per-query work, and dialing inside the
	// window would charge every accept, goroutine and buffer to whichever
	// queries happened to follow. The mark below closes the window those
	// accepts landed in — along with the teardown of the previous
	// window's connections — and opens the measured one.
	var conns []net.Conn
	var counts []int
	if flavor == FlavorTCP {
		conns, counts = prepareTCP(t, target, ops)
		defer func() {
			for _, c := range conns {
				_ = c.Close()
			}
		}()
		// One query per connection before the window opens. Dialing
		// returns when the handshake completes, which says nothing about
		// the server having reached its Accept — and an accept that lands
		// inside the window bills a connection's socket, buffers and
		// goroutine to whichever queries happen to follow it. A served
		// reply is proof the connection is fully up.
		settle := make([]int, len(conns))
		for i := range settle {
			settle[i] = 1
		}
		floodTCPOn(t, conns, settle)

		child.quiesce(t)
		child.markBoth(t)
	}

	started := time.Now()
	switch flavor {
	case FlavorTCP:
		floodTCPOn(t, conns, counts)
	default:
		floodUDP(t, target, ops)
	}
	child.quiesce(t)
	elapsed := time.Since(started)
	mallocs, m := child.markBoth(t)
	w := window{
		ops: ops, mallocs: mallocs, served: m.served,
		other: m.other, parked: m.parked, unknown: m.unknown, elapsed: elapsed,
	}
	if m.served != 0 || m.unknown != 0 || os.Getenv("ZEROGATE_ALL_SITES") != "" {
		// Collected here rather than at the verdict: the offender list
		// describes the window that just closed, and the next mark
		// replaces it.
		w.offenders = child.offenders(t)
	}
	return w
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

func startHarness(bin, bind string, extra []string) (*harnessProc, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "ZEROGATE_BIND="+bind)
	cmd.Env = append(cmd.Env, extra...)
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

// send writes one command and returns the first reply line carrying
// prefix.
func (h *harnessProc) send(t *testing.T, cmd, prefix string) string {
	t.Helper()
	if _, err := h.stdin.WriteString(cmd + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := h.stdin.Flush(); err != nil {
		t.Fatal(err)
	}
	for h.stdout.Scan() {
		if line := h.stdout.Text(); strings.HasPrefix(line, prefix) {
			return strings.TrimPrefix(line, prefix)
		}
	}
	t.Fatalf("harness closed before %s reply: %v", cmd, h.stdout.Err())
	return ""
}

// quiesce blocks until the server holds no job slab. It is the window
// boundary: the point where every reply has left and every slab that
// carried one has been released.
func (h *harnessProc) quiesce(t *testing.T) {
	t.Helper()
	if v := h.send(t, "quiesce", "QUIESCED "); v != "ok" {
		t.Fatalf("server did not quiesce (%s): slabs are still outstanding, "+
			"so a window boundary cannot be placed here", v)
	}
}

// markBoth closes the current window and opens the next, returning the
// process-wide malloc count and the objects allocated on serving
// goroutines since the previous mark.
func (h *harnessProc) markBoth(t *testing.T) (uint64, marks) {
	t.Helper()
	fields := strings.Fields(h.send(t, "mark", "MALLOCS "))
	if len(fields) != 9 || fields[1] != "SERVED" || fields[3] != "OTHER" ||
		fields[5] != "PARKED" || fields[7] != "UNKNOWN" {
		t.Fatalf("bad mark reply %q", strings.Join(fields, " "))
	}
	mallocs, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		t.Fatalf("bad malloc count %q: %v", fields[0], err)
	}
	var m marks
	for _, f := range []struct {
		name string
		at   int
		into *int64
	}{
		{"served", 2, &m.served},
		{"other", 4, &m.other},
		{"parked", 6, &m.parked},
		{"unknown", 8, &m.unknown},
	} {
		v, err := strconv.ParseInt(fields[f.at], 10, 64)
		if err != nil {
			t.Fatalf("bad %s count %q: %v", f.name, fields[f.at], err)
		}
		*f.into = v
	}
	return mallocs, m
}

// marks is one mark's classification of the window that just closed.
type marks struct {
	served  int64 // the server's own code, on a serving goroutine
	other   int64 // anywhere else in the server
	parked  int64 // of other: scheduler bookkeeping for a parked serving goroutine
	unknown int64 // stacks too deep to classify at all
}

// offenders returns the allocating sites behind a nonzero served count,
// so a failure names the code that has to change.
func (h *harnessProc) offenders(t *testing.T) []string {
	t.Helper()
	if _, err := h.stdin.WriteString("offenders\n"); err != nil {
		t.Fatal(err)
	}
	if err := h.stdin.Flush(); err != nil {
		t.Fatal(err)
	}
	var out []string
	for h.stdout.Scan() {
		line := h.stdout.Text()
		if line == "END" {
			return out
		}
		if strings.HasPrefix(line, "OFFENDER ") {
			out = append(out, strings.TrimPrefix(line, "OFFENDER "))
		}
	}
	t.Fatalf("harness closed before offender list: %v", h.stdout.Err())
	return nil
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
