package doq

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/zlog"
)

var doqProtos = []string{"doq", "doq-i02", "dq", "doq-i00", "doq-i01", "doq-i11"}

const (
	minMsgHeaderSize = 14 // fixed msg header size 12 + quic prefix size 2
	ProtocolError    = 0x2
	NoError          = 0x0
	maxMsgSize       = 65535            // Maximum DNS message size
	tlsMinVersion    = tls.VersionTLS13 // DoQ requires TLS 1.3+
)

var (
	errServerClosed = errors.New("doq server closed")
	errMsgTooSmall  = errors.New("dns message too small")
	errInvalidMsg   = errors.New("invalid dns message")
)

// Server implements DNS-over-QUIC server
type Server struct {
	Addr    string
	Handler dns.Handler

	ln *quic.Listener
}

// Message pool for better memory management
var msgPool = sync.Pool{
	New: func() any {
		return new(dns.Msg)
	},
}

func acquireMsg() *dns.Msg {
	return msgPool.Get().(*dns.Msg)
}

func releaseMsg(m *dns.Msg) {
	m.Question = nil
	m.Answer = nil
	m.Ns = nil
	m.Extra = nil
	msgPool.Put(m)
}

func (s *Server) ListenAndServeQUIC(tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   doqProtos,
		MinVersion:   tlsMinVersion,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:         5 * time.Second,
		MaxStreamReceiveWindow: maxMsgSize,
		KeepAlivePeriod:        30 * time.Second,
	}

	listener, err := quic.ListenAddr(s.Addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	s.ln = listener

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) Shutdown() error {
	if s.ln == nil {
		return nil
	}

	err := s.ln.Close()

	// quic.ErrServerClosed is expected when closing
	if err != nil && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *Server) handleConnection(conn quic.Connection) {
	for {
		stream, err := conn.AcceptStream(context.Background())
		if err != nil {
			if errors.Is(err, quic.ErrServerClosed) {
				return
			}
			zlog.Debug("Failed to accept stream", "error", err)
			_ = conn.CloseWithError(NoError, "")
			return
		}

		go s.handleStream(conn, stream)
	}
}

func (s *Server) handleStream(conn quic.Connection, stream quic.Stream) {
	defer stream.Close()

	// Limit read size to prevent DoS
	limitedReader := io.LimitReader(stream, maxMsgSize)
	buf, err := io.ReadAll(limitedReader)
	if err != nil {
		zlog.Debug("Failed to read stream", "error", err)
		return
	}

	if len(buf) < minMsgHeaderSize {
		zlog.Debug("Message too small", "size", len(buf))
		return
	}

	// Extract message length prefix
	msgLen := binary.BigEndian.Uint16(buf[:2])
	if int(msgLen) != len(buf)-2 {
		zlog.Debug("Message length mismatch", "expected", msgLen, "actual", len(buf)-2)
		return
	}

	req := acquireMsg()
	defer releaseMsg(req)

	if err := req.Unpack(buf[2:]); err != nil {
		zlog.Debug("Failed to unpack DNS message", "error", err)
		return
	}

	// Generate new ID for security
	req.Id = dns.Id()

	w := &ResponseWriter{Conn: conn, Stream: stream}
	s.Handler.ServeDNS(w, req)
}
