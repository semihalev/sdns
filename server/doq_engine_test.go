package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsclient"
	"github.com/semihalev/sdns/middleware"
)

// startDoQ serves the handler on a DoQ listener over loopback.
func startDoQ(t *testing.T, h rawHandler, plan resourcePlan) (*doqListener, string) {
	t.Helper()
	l := newDOQListener("127.0.0.1:0", h, &fakeCerts{cfg: minimalTLSConfig(t)}, time.Second, plan)
	if err := l.Bind(context.Background()); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- l.Serve(context.Background()) }()
	t.Cleanup(func() {
		_ = l.Shutdown(context.Background())
		if err := <-served; err != nil {
			t.Errorf("serve: %v", err)
		}
	})
	for deadline := time.Now().Add(3 * time.Second); !l.Serving(); {
		if time.Now().After(deadline) {
			t.Fatal("doq listener did not come up")
		}
		time.Sleep(time.Millisecond)
	}
	return l, l.pc.LocalAddr().String()
}

func dialDoQ(t *testing.T, addr string, alpn ...string) (*quic.Conn, error) {
	t.Helper()
	if len(alpn) == 0 {
		alpn = []string{"doq"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: alpn}, //nolint:gosec // loopback test server
		&quic.Config{MaxIdleTimeout: 10 * time.Second})
	if err == nil {
		t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	}
	return conn, err
}

// answer is a rawHandler that answers every query with one A record,
// through the job's Msg path.
var answer = rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
	req := new(dns.Msg)
	if err := req.Unpack(raw); err != nil {
		return false
	}
	resp := new(dns.Msg)
	resp.SetReply(req)
	rr, _ := dns.NewRR(req.Question[0].Name + " 60 IN A 192.0.2.53")
	resp.Answer = []dns.RR{rr}
	_ = w.WriteMsg(resp)
	return true
})

func framedQuery(t *testing.T, id uint16, mutate func(*dns.Msg)) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion("doq.test.", dns.TypeA)
	m.Id = id
	if mutate != nil {
		mutate(m)
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(raw))), raw...) //nolint:gosec // small
}

// exchange sends payload on a fresh stream, FIN after it unless open,
// and reads one framed reply.
func exchange(conn *quic.Conn, payload []byte, open bool) (*dns.Msg, error) {
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		return nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := stream.Write(payload); err != nil {
		return nil, err
	}
	if !open {
		_ = stream.Close()
	}
	body, err := io.ReadAll(stream)
	if err != nil {
		return nil, err
	}
	if len(body) < 2 || int(binary.BigEndian.Uint16(body)) != len(body)-2 {
		return nil, errors.New("reply not framed as one message")
	}
	m := new(dns.Msg)
	return m, m.Unpack(body[2:])
}

func doqPlan(conns, jobs int) resourcePlan {
	return resourcePlan{doqConns: conns, doqJobs: jobs}
}

// A query is answered on its stream, framed, with message ID zero, and
// the connection serves the next.
func TestDoQAnswers(t *testing.T) {
	_, addr := startDoQ(t, answer, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		resp, err := exchange(conn, framedQuery(t, 0, nil), false)
		if err != nil {
			t.Fatal(err)
		}
		if resp.Id != 0 || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
			t.Fatalf("reply %v, want one answer under ID 0", resp)
		}
	}
}

// RFC 9250 §4.1: "doq" is the one ALPN token; the drafts' are refused.
func TestDoQOffersOnlyTheRFCToken(t *testing.T) {
	_, addr := startDoQ(t, answer, doqPlan(4, 4))
	for _, alpn := range []string{"doq-i02", "doq-i00", "dq"} {
		if _, err := dialDoQ(t, addr, alpn); err == nil {
			t.Errorf("handshake with %q succeeded", alpn)
		}
	}
	if _, err := dialDoQ(t, addr, "doq-i02", "doq"); err != nil {
		t.Errorf("a client offering doq among others: %v", err)
	}
}

// RFC 9250 §4.3.3: these close the connection with DOQ_PROTOCOL_ERROR.
func TestDoQProtocolErrors(t *testing.T) {
	q := framedQuery(t, 0, nil)
	for _, tc := range []struct {
		name    string
		payload []byte
		open    bool
	}{
		{"non-zero message ID", framedQuery(t, 4242, nil), false},
		{"two queries on one stream", append(append([]byte{}, q...), q...), false},
		{"FIN before the whole message", q[:len(q)-3], false},
		{"length below a header", []byte{0, 5, 1, 2, 3, 4, 5}, false},
		{"edns-tcp-keepalive option", framedQuery(t, 0, func(m *dns.Msg) {
			m.SetEdns0(1232, false)
			opt := m.IsEdns0()
			opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
		}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, addr := startDoQ(t, answer, doqPlan(4, 4))
			conn, err := dialDoQ(t, addr)
			if err != nil {
				t.Fatal(err)
			}
			_, err = exchange(conn, tc.payload, tc.open)
			var appErr *quic.ApplicationError
			if !errors.As(err, &appErr) || appErr.ErrorCode != doqProtocolError || !appErr.Remote {
				t.Fatalf("got %v, want the connection closed with DOQ_PROTOCOL_ERROR", err)
			}
		})
	}
}

// §4.3.3 also forbids client-opened unidirectional streams: none are
// allowed.
func TestDoQRefusesUnidirectionalStreams(t *testing.T) {
	_, addr := startDoQ(t, answer, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.OpenUniStream(); err == nil {
		t.Fatal("a unidirectional stream opened")
	}
}

// A stream the client abandons costs that stream only (§4.3.1): the
// connection keeps serving the others.
func TestDoQAbandonedStreamLeavesTheConnection(t *testing.T) {
	_, addr := startDoQ(t, answer, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	q := framedQuery(t, 0, nil)
	if _, err := stream.Write(q[:4]); err != nil {
		t.Fatal(err)
	}
	stream.CancelWrite(doqRequestCanceled)
	stream.CancelRead(doqRequestCanceled)

	if resp, err := exchange(conn, q, false); err != nil || len(resp.Answer) != 1 {
		t.Fatalf("after an abandoned stream: %v, %v", resp, err)
	}
}

// A query with no slab free is refused on its stream with
// DOQ_EXCESSIVE_LOAD, and the connection serves on once one is.
func TestDoQStreamOverLoadIsRefused(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	var once sync.Once
	blocking := rawHandlerFunc(func(w middleware.Transport, raw []byte, rt time.Time) bool {
		once.Do(func() {
			entered <- struct{}{}
			<-release
		})
		return answer(w, raw, rt)
	})
	_, addr := startDoQ(t, blocking, doqPlan(4, 1))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	q := framedQuery(t, 0, nil)
	first := make(chan error, 1)
	go func() { _, err := exchange(conn, q, false); first <- err }()
	<-entered

	_, err = exchange(conn, q, false)
	var streamErr *quic.StreamError
	if !errors.As(err, &streamErr) || streamErr.ErrorCode != doqExcessiveLoad {
		t.Fatalf("got %v, want the stream refused with DOQ_EXCESSIVE_LOAD", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the admitted query: %v", err)
	}
	if _, err := exchange(conn, q, false); err != nil {
		t.Fatalf("after the slab came back: %v", err)
	}
}

// A connection past the cap is closed with DOQ_EXCESSIVE_LOAD.
func TestDoQConnectionCap(t *testing.T) {
	_, addr := startDoQ(t, answer, doqPlan(1, 4))
	first, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := exchange(first, framedQuery(t, 0, nil), false); err != nil {
		t.Fatal(err)
	}
	second, err := dialDoQ(t, addr)
	if err == nil {
		_, err = exchange(second, framedQuery(t, 0, nil), false)
	}
	var appErr *quic.ApplicationError
	if !errors.As(err, &appErr) || appErr.ErrorCode != doqExcessiveLoad {
		t.Fatalf("got %v, want the second connection closed with DOQ_EXCESSIVE_LOAD", err)
	}
}

// A query the handler does not answer resets the stream with
// DOQ_INTERNAL_ERROR rather than finishing it empty (§4.3.2).
func TestDoQUnansweredStreamIsReset(t *testing.T) {
	silent := rawHandlerFunc(func(middleware.Transport, []byte, time.Time) bool { return true })
	_, addr := startDoQ(t, silent, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	_, err = exchange(conn, framedQuery(t, 0, nil), false)
	var streamErr *quic.StreamError
	if !errors.As(err, &streamErr) || streamErr.ErrorCode != doqInternalError {
		t.Fatalf("got %v, want the stream reset with DOQ_INTERNAL_ERROR", err)
	}
}

// A reply larger than the slab's TX still goes out whole, framed, ID 0;
// an undecodable query is answered FORMERR, a foreign opcode NOTIMP, both
// under ID 0.
func TestDoQReplyShapes(t *testing.T) {
	big := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil {
			return false
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		for i := range 1200 {
			rr, _ := dns.NewRR("big.doq.test. 60 IN A 198.51." + string(rune('0'+i%10)) + ".1")
			resp.Answer = append(resp.Answer, rr)
		}
		resp.Compress = false
		_ = w.WriteMsg(resp)
		return true
	})
	_, addr := startDoQ(t, big, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := exchange(conn, framedQuery(t, 0, nil), false)
	if err != nil || resp.Id != 0 || len(resp.Answer) != 1200 || resp.Len() <= tcpSmallReply {
		t.Fatalf("large reply: %d answers, ID %d, %v", len(resp.Answer), resp.Id, err)
	}

	resp, err = exchange(conn, framedQuery(t, 0, func(m *dns.Msg) { m.Opcode = 7 }), false)
	if err != nil || resp.Rcode != dns.RcodeNotImplemented || resp.Id != 0 {
		t.Fatalf("foreign opcode: %v, %v", resp, err)
	}
	// A question name whose compression pointer points at itself never
	// decodes, as in the UDP engine's test.
	body := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 1, 0, 1}
	garbage := append(binary.BigEndian.AppendUint16(nil, uint16(len(body))), body...) //nolint:gosec // small
	resp, err = exchange(conn, garbage, false)
	if err != nil || resp.Rcode != dns.RcodeFormatError || resp.Id != 0 {
		t.Fatalf("undecodable query: %v, %v", resp, err)
	}
}

// The slabs' goroutines end with the slabs: on trim, and at shutdown.
func TestDoQSlabGoroutinesEnd(t *testing.T) {
	before := runtime.NumGoroutine()
	l, addr := startDoQ(t, answer, doqPlan(4, 8))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = exchange(conn, framedQuery(t, 0, nil), false)
		}()
	}
	wg.Wait()
	for deadline := time.Now().Add(2 * time.Second); !l.Quiesced(); {
		if time.Now().After(deadline) {
			t.Fatal("slabs never came back")
		}
		time.Sleep(time.Millisecond)
	}
	if n := l.TrimIdleMemory(); n == 0 {
		t.Fatal("trim dropped no slab")
	}
	_ = conn.CloseWithError(0, "")
	if err := l.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(3 * time.Second); runtime.NumGoroutine() > before+2; {
		if time.Now().After(deadline) {
			t.Fatalf("goroutines %d, started with %d", runtime.NumGoroutine(), before)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Through the real pipeline, a cached answer goes out on the byte path:
// the cache serves it as bytes into the stream's slab, the reply carries
// message ID zero, the answer, and the client's cookie echoed in its OPT.
func TestDoQCacheHitTakesTheBytePath(t *testing.T) {
	conn := doqBenchServer(t)
	query := framedQuery(t, 0, func(m *dns.Msg) {
		m.Question[0].Name = "bytes.doq.test."
		m.SetEdns0(1232, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"})
	})
	if _, err := exchange(conn, query, false); err != nil { // the miss that fills the cache
		t.Fatal(err)
	}

	before := wireOutcomes()
	resp, err := exchange(conn, query, false)
	if err != nil {
		t.Fatal(err)
	}
	if served := wireOutcomes()["served"] - before["served"]; served != 1 {
		t.Fatalf("the hit was not served as bytes: %s", wireOutcomeDelta(before))
	}
	if resp.Id != 0 || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) != 1 {
		t.Fatalf("reply %v, want the cached answer under ID 0", resp)
	}
	opt := resp.IsEdns0()
	if opt == nil {
		t.Fatal("no OPT in the reply")
	}
	var cookie string
	for _, o := range opt.Option {
		if c, ok := o.(*dns.EDNS0_COOKIE); ok {
			cookie = c.Cookie
		}
	}
	if len(cookie) != 80 || cookie[:16] != "0102030405060708" {
		t.Fatalf("cookie %q, want the client half echoed with a server cookie", cookie)
	}
}

// Once shutdown begins no stream is admitted, on any connection, while
// the one already in flight is allowed to finish.
func TestDoQDrainAdmitsNoNewStream(t *testing.T) {
	release := make(chan struct{})
	var entered atomic.Int32
	h := rawHandlerFunc(func(w middleware.Transport, raw []byte, rt time.Time) bool {
		if entered.Add(1) == 1 {
			<-release
		}
		return answer(w, raw, rt)
	})
	l, addr := startDoQ(t, h, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	q := framedQuery(t, 0, nil)
	first := make(chan error, 1)
	go func() { _, err := exchange(conn, q, false); first <- err }()
	for entered.Load() == 0 {
		time.Sleep(time.Millisecond)
	}

	stopped := make(chan struct{})
	go func() { _ = l.Shutdown(context.Background()); close(stopped) }()
	<-l.engine.closing

	if _, err := exchange(conn, q, false); err == nil {
		t.Fatal("a stream opened during the drain was answered")
	}
	if n := entered.Load(); n != 1 {
		t.Fatalf("the handler was entered %d times, want only the stream admitted before the drain", n)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatalf("the stream admitted before the drain: %v", err)
	}
	<-stopped
}

// Admission and the drain race freely here; under -race a counter that
// admission can still add to after the drain started waiting is reported.
func TestDoQShutdownUnderLoad(t *testing.T) {
	for range 5 {
		l, addr := startDoQ(t, answer, doqPlan(4, 8))
		conn, err := dialDoQ(t, addr)
		if err != nil {
			t.Fatal(err)
		}
		q := framedQuery(t, 0, nil)
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 20 {
					if _, err := exchange(conn, q, false); err != nil {
						return
					}
				}
			}()
		}
		time.Sleep(5 * time.Millisecond)
		_ = l.Shutdown(context.Background())
		wg.Wait()
		if !l.Quiesced() {
			t.Fatal("a slab is still out after shutdown")
		}
	}
}

// ctxAnswer is a handler that takes the stream's context and waits on it
// instead of answering.
type ctxAnswer struct {
	entered  chan struct{}
	canceled chan struct{}
}

func (h *ctxAnswer) ServeRaw(w middleware.Transport, raw []byte, rt time.Time) bool {
	return h.ServeRawContext(context.Background(), w, raw, rt)
}

func (h *ctxAnswer) ServeRawContext(ctx context.Context, _ middleware.Transport, _ []byte, _ time.Time) bool {
	h.entered <- struct{}{}
	select {
	case <-ctx.Done():
		close(h.canceled)
	case <-time.After(3 * time.Second):
	}
	return true
}

// A client cancelling a query in flight (§4.3.1) reaches the work it
// started, which lets go of its slab.
func TestDoQCancelReachesTheWorkInFlight(t *testing.T) {
	h := &ctxAnswer{entered: make(chan struct{}, 1), canceled: make(chan struct{})}
	l, addr := startDoQ(t, h, doqPlan(4, 4))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(framedQuery(t, 0, nil)); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	<-h.entered
	stream.CancelRead(doqRequestCanceled)

	select {
	case <-h.canceled:
	case <-time.After(2 * time.Second):
		t.Fatal("the work in flight never saw the cancellation")
	}
	for deadline := time.Now().Add(2 * time.Second); !l.Quiesced(); {
		if time.Now().After(deadline) {
			t.Fatal("the slab was not given back")
		}
		time.Sleep(time.Millisecond)
	}
}

// A reply cut short by its write deadline resets the stream: a FIN after
// part of a message would be a protocol error (§4.3.3).
func TestDoQCutReplyResetsTheStream(t *testing.T) {
	big := rawHandlerFunc(func(w middleware.Transport, raw []byte, _ time.Time) bool {
		req := new(dns.Msg)
		if err := req.Unpack(raw); err != nil {
			return false
		}
		resp := new(dns.Msg)
		resp.SetReply(req)
		// About 56KB compressed: under the message ceiling, far over the
		// client's 1KB window.
		for range 3500 {
			rr, _ := dns.NewRR("big.doq.test. 60 IN A 198.51.100.1")
			resp.Answer = append(resp.Answer, rr)
		}
		resp.Compress = true
		if err := w.WriteMsg(resp); err == nil {
			t.Error("the reply went out whole through a shut window")
		}
		return true
	})
	_, addr := startDoQ(t, big, doqPlan(4, 4))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, addr,
		&tls.Config{InsecureSkipVerify: true, NextProtos: []string{"doq"}}, //nolint:gosec // loopback test server
		&quic.Config{MaxIdleTimeout: 10 * time.Second, InitialStreamReceiveWindow: 1024, MaxStreamReceiveWindow: 1024})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.CloseWithError(0, "") })
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Write(framedQuery(t, 0, nil)); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	// Past the server's write deadline, with the window shut.
	time.Sleep(doqQueryWait + 500*time.Millisecond)
	_ = stream.SetReadDeadline(time.Now().Add(3 * time.Second))
	body, err := io.ReadAll(stream)
	var streamErr *quic.StreamError
	if !errors.As(err, &streamErr) || streamErr.ErrorCode != doqInternalError {
		t.Fatalf("read %d bytes, %v; want the stream reset with DOQ_INTERNAL_ERROR", len(body), err)
	}
}

// A query larger than the slab's receive class is read into a buffer of
// its own: the slab goes back at the size the plan prices it at.
func TestDoQLargeQueryLeavesTheSlabItsSize(t *testing.T) {
	l, addr := startDoQ(t, answer, doqPlan(4, 1))
	conn, err := dialDoQ(t, addr)
	if err != nil {
		t.Fatal(err)
	}
	q := framedQuery(t, 0, func(m *dns.Msg) {
		m.SetEdns0(1232, false)
		opt := m.IsEdns0()
		opt.Option = append(opt.Option, &dns.EDNS0_PADDING{Padding: make([]byte, 60000)})
	})
	if resp, err := exchange(conn, q, false); err != nil || len(resp.Answer) != 1 {
		t.Fatalf("large query: %v, %v", resp, err)
	}
	for deadline := time.Now().Add(2 * time.Second); !l.Quiesced(); {
		if time.Now().After(deadline) {
			t.Fatal("the slab was not given back")
		}
		time.Sleep(time.Millisecond)
	}
	j := l.engine.cache.get(0)
	if j == nil {
		t.Fatal("no slab parked")
	}
	defer stopJob(j)
	if cap(j.rx) != tcpSmallFrame || len(j.tx) != dnsclient.FramePrefixLen+tcpSmallReply {
		t.Fatalf("parked slab holds RX %d and TX %d bytes, want %d and %d",
			cap(j.rx), len(j.tx), tcpSmallFrame, dnsclient.FramePrefixLen+tcpSmallReply)
	}
}

// The server carries a parent's cancellation into the work a query
// starts, on the strict path (through the carrier's detach) and on the
// decoded one alike.
func TestServeRawContextCarriesCancellation(t *testing.T) {
	saw := make(chan bool, 1)
	middleware.Reset()
	t.Cleanup(middleware.Reset)
	middleware.Register("waiter", func(*config.Config) middleware.Handler {
		return middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
			ctx, _ = ch.Materialize(ctx)
			select {
			case <-ctx.Done():
				saw <- true
			case <-time.After(2 * time.Second):
				saw <- false
			}
			ch.Cancel()
		})
	})
	cfg := &config.Config{Bind: "127.0.0.1:0"}
	cfg.QueryTimeout.Duration = 10 * time.Second
	middleware.Setup(cfg)
	s := New(cfg)

	for _, tc := range []struct {
		name   string
		opcode int
	}{{"strict", dns.OpcodeQuery}, {"decoded", dns.OpcodeNotify}} {
		t.Run(tc.name, func(t *testing.T) {
			m := new(dns.Msg)
			m.SetQuestion("cancel.test.", dns.TypeA)
			m.Opcode = tc.opcode
			raw, err := m.Pack()
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(50*time.Millisecond, cancel)
			job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 50), Port: 4242}}
			s.ServeRawContext(ctx, job, raw, time.Now())
			if !<-saw {
				t.Fatal("the work never saw the parent's cancellation")
			}
		})
	}
}
