package server

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/semihalev/zlog/v2"
)

// udpListener runs the owned UDP engine (udp_engine.go) over one or more
// sockets. The socket strategy is platform-dependent (see reuseport_*.go):
//
//   - When kernelLoadBalances is true (Linux), N sockets are opened on
//     the same port with SO_REUSEPORT; the kernel distributes datagrams
//     across them by 4-tuple hash and each socket gets one reader.
//   - Otherwise a single socket carries a single reader; parallelism
//     comes from the engine's fixed worker pool either way.
//
// A wildcard bind arms the pktinfo machinery (pktinfo_linux.go) so
// replies leave from the address the query arrived on.
type udpListener struct {
	addr    string
	handler rawHandler
	sockets int
	workers int
	queue   int
	timeout time.Duration

	mu       sync.Mutex
	pcs      []*net.UDPConn
	engine   *udpEngine
	done     chan struct{}
	shutdown sync.Once
	closing  atomic.Bool
	drainErr error
	serving  atomic.Bool
}

func newUDPListener(addr string, h rawHandler, timeout time.Duration, workers, queue int) *udpListener {
	return &udpListener{
		addr:    addr,
		handler: h,
		sockets: defaultUDPWorkers(),
		workers: workers,
		queue:   queue,
		timeout: timeout,
	}
}

func (l *udpListener) Proto() string  { return "udp" }
func (l *udpListener) Addr() string   { return l.addr }
func (l *udpListener) Critical() bool { return true }
func (l *udpListener) Serving() bool  { return l.serving.Load() }

// bindWildcard reports whether addr's host is absent or unspecified —
// the binds that need destination-address recovery on replies.
func bindWildcard(addr string) (wildcard, v6 bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return true, false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false, false
	}
	return ip.IsUnspecified(), ip.To4() == nil
}

func (l *udpListener) Bind(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.engine != nil {
		return errors.New("udp listener: Bind called twice")
	}

	wildcard, v6 := bindWildcard(l.addr)
	control := reusePortControl
	if wildcard {
		control = pktinfoControl("udp", v6)
	}
	lc := net.ListenConfig{Control: control}

	sockets := 1
	if kernelLoadBalances {
		sockets = l.sockets
	}
	addr := l.addr
	for i := 0; i < sockets; i++ {
		pc, err := lc.ListenPacket(ctx, "udp", addr)
		if err != nil {
			for _, open := range l.pcs {
				_ = open.Close()
			}
			l.pcs = nil
			return err
		}
		udpConn, ok := pc.(*net.UDPConn)
		if !ok {
			_ = pc.Close()
			for _, open := range l.pcs {
				_ = open.Close()
			}
			l.pcs = nil
			return errors.New("udp listener: unexpected packet conn type")
		}
		l.pcs = append(l.pcs, udpConn)
		if i == 0 {
			// Lock subsequent sockets to the kernel-assigned port so
			// every socket joins the same SO_REUSEPORT group when the
			// configured address ends in ":0".
			addr = pc.LocalAddr().String()
		}
	}

	l.engine = newUDPEngine(l.handler, l.pcs, wildcard, l.workers, l.queue)
	l.done = make(chan struct{})
	return nil
}

func (l *udpListener) Serve(_ context.Context) error {
	l.mu.Lock()
	engine := l.engine
	done := l.done
	l.mu.Unlock()
	if engine == nil {
		return errListenerNotBound
	}

	zlog.Info("DNS server listening", "net", "udp", "addr", l.addr,
		"sockets", len(engine.pcs), "workers", engine.workers)
	engine.start()
	l.serving.Store(true)
	defer l.serving.Store(false)

	// Readers exit only when their sockets close. If that happens outside
	// Shutdown the listener is dead; make it loud instead of silent.
	go func() {
		engine.readers.Wait()
		if !l.closing.Load() {
			zlog.Error("UDP readers exited outside shutdown", "addr", l.addr)
			recordListenerErr("udp")
		}
	}()

	<-done
	return l.drainErr
}

// Shutdown is the listener-scope barrier: stop admission by closing the
// sockets (blocked reads wake with net.ErrClosed), join the readers,
// close the ready queue, and drain the workers within the deadline.
func (l *udpListener) Shutdown(_ context.Context) error {
	l.mu.Lock()
	engine := l.engine
	pcs := append([]*net.UDPConn(nil), l.pcs...)
	l.mu.Unlock()
	if engine == nil {
		return nil
	}

	l.shutdown.Do(func() {
		timeout := l.timeout
		if timeout <= 0 {
			timeout = 5 * time.Second
		}
		zlog.Info("DNS server stopping", "net", "udp", "addr", l.addr)

		// Admission stops now; readers waking on closed sockets are the
		// intended path, not a failure.
		l.closing.Store(true)
		for _, pc := range pcs {
			if err := pc.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				l.drainErr = errors.Join(l.drainErr, err)
			}
		}
		if err := engine.stopAndDrain(time.Now().Add(timeout)); err != nil {
			l.drainErr = errors.Join(l.drainErr, err)
		}
		close(l.done)
	})
	return l.drainErr
}
