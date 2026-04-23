package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/zlog/v2"
)

// udpListener spreads UDP receive work across N goroutines. The split
// strategy is platform-dependent (see reuseport_*.go):
//
//   - When kernelLoadBalances is true (Linux), N sockets are opened on
//     the same port with SO_REUSEPORT; the kernel distributes datagrams
//     across them by 4-tuple hash and each goroutine owns its own
//     dns.Server + socket.
//   - When kernelLoadBalances is false (Darwin / BSDs / Windows), one
//     socket is shared by N dns.Server goroutines. Go's netpoller lets
//     concurrent ReadFrom callers each pick off a packet as it lands
//     in the kernel queue, which parallelises the syscall + copy +
//     goroutine-spawn cost across cores without needing kernel support.
//
// Either way the number of receive goroutines is the same, and callers
// don't need to know which path is active.
type udpListener struct {
	addr    string
	handler dns.Handler
	workers int
	timeout time.Duration

	mu      sync.Mutex
	pcs     []net.PacketConn
	srvs    []*dns.Server
	serving atomic.Bool
}

func newUDPListener(addr string, h dns.Handler, timeout time.Duration) *udpListener {
	return &udpListener{
		addr:    addr,
		handler: h,
		workers: defaultUDPWorkers(),
		timeout: timeout,
	}
}

func (l *udpListener) Proto() string  { return "udp" }
func (l *udpListener) Addr() string   { return l.addr }
func (l *udpListener) Critical() bool { return true }
func (l *udpListener) Serving() bool  { return l.serving.Load() }

func (l *udpListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.srvs) != 0 {
		return errors.New("udp listener: Bind called twice")
	}

	if kernelLoadBalances {
		return l.bindPerWorker(ctx)
	}
	return l.bindShared(ctx)
}

// bindPerWorker opens one SO_REUSEPORT socket per worker. Linux path.
//
// After the first socket is bound, subsequent workers bind to that
// socket's resolved LocalAddr rather than the configured string. This
// matters when l.addr ends in ":0" — otherwise each ListenPacket
// would pick its own ephemeral port and the workers would live on
// unrelated ports instead of sharing one endpoint (which is the
// whole point of the SO_REUSEPORT fan-out and is expected behaviour
// for dynamic-port tests / embedded callers).
func (l *udpListener) bindPerWorker(ctx context.Context) error {
	lc := net.ListenConfig{Control: reusePortControl}
	addr := l.addr
	for i := 0; i < l.workers; i++ {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, open := range l.pcs {
				_ = open.Close()
			}
			l.pcs = nil
			l.srvs = nil
			return err
		}
		l.pcs = append(l.pcs, pc)
		l.srvs = append(l.srvs, &dns.Server{
			PacketConn: pc,
			Net:        "udp",
			Handler:    l.handler,
		})
		if i == 0 {
			// Lock subsequent workers to the kernel-assigned port so
			// every worker joins the same SO_REUSEPORT group.
			addr = pc.LocalAddr().String()
		}
	}
	return nil
}

// bindShared opens a single socket that every worker reads from.
// Non-Linux path — SO_REUSEPORT wouldn't distribute anyway.
func (l *udpListener) bindShared(ctx context.Context) error {
	var lc net.ListenConfig
	pc, err := lc.ListenPacket(ctx, "udp", l.addr)
	if err != nil {
		return err
	}
	l.pcs = []net.PacketConn{pc}
	for i := 0; i < l.workers; i++ {
		l.srvs = append(l.srvs, &dns.Server{
			PacketConn: pc,
			Net:        "udp",
			Handler:    l.handler,
		})
	}
	return nil
}

func (l *udpListener) Serve(_ context.Context) error {
	l.mu.Lock()
	srvs := append([]*dns.Server(nil), l.srvs...)
	l.mu.Unlock()
	if len(srvs) == 0 {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "udp", "addr", l.addr, "workers", len(srvs))
	l.serving.Store(true)
	defer l.serving.Store(false)

	errs := make(chan error, len(srvs))
	var wg sync.WaitGroup
	for _, srv := range srvs {
		wg.Add(1)
		go func(srv *dns.Server) {
			defer wg.Done()
			if err := srv.ActivateAndServe(); err != nil && !errors.Is(err, net.ErrClosed) {
				errs <- err
			}
		}(srv)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

func (l *udpListener) Shutdown(_ context.Context) error {
	l.mu.Lock()
	srvs := append([]*dns.Server(nil), l.srvs...)
	pcs := append([]net.PacketConn(nil), l.pcs...)
	l.mu.Unlock()
	if len(srvs) == 0 {
		return nil
	}

	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	zlog.Info("DNS server stopping", "net", "udp", "addr", l.addr)

	// Always close our own PacketConns: miekg/dns's ShutdownContext
	// is a no-op when Serve hasn't started, which is exactly the
	// bind-without-serve path that bindAll's cleanup runs.
	var joined []error
	for _, srv := range srvs {
		if err := srv.ShutdownContext(shutdownCtx); err != nil && !ignoreShutdownErr(err) {
			joined = append(joined, err)
		}
	}
	for _, pc := range pcs {
		if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			joined = append(joined, err)
		}
	}
	return errors.Join(joined...)
}
