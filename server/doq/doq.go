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

// Server implements DNS-over-QUIC server.
type Server struct {
	Addr    string
	Handler dns.Handler

	mu sync.RWMutex
	ln *quic.Listener
}

// Message pool for better memory management.
var msgPool = sync.Pool{
	New: func() any {
		return new(dns.Msg)
	},
}

func acquireMsg() *dns.Msg {
	return msgPool.Get().(*dns.Msg)
}

func releaseMsg(m *dns.Msg) {
	// Clear all fields to ensure clean state for reuse
	m.Id = 0
	m.Response = false
	m.Opcode = 0
	m.Authoritative = false
	m.Truncated = false
	m.RecursionDesired = false
	m.RecursionAvailable = false
	m.Zero = false
	m.AuthenticatedData = false
	m.CheckingDisabled = false
	m.Rcode = 0
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

	return s.ListenAndServeQUICWithConfig(tlsConfig)
}

// ListenAndServeQUICWithConfig serves with a custom TLS config
func (s *Server) ListenAndServeQUICWithConfig(tlsConfig *tls.Config) error {
	// Ensure DOQ protocols are set
	if tlsConfig.NextProtos == nil {
		tlsConfig = tlsConfig.Clone()
		tlsConfig.NextProtos = doqProtos
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:         5 * time.Second,
		MaxStreamReceiveWindow: maxMsgSize,
	}

	listener, err := quic.ListenAddr(s.Addr, tlsConfig, quicConfig)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.ln = listener
	s.mu.Unlock()

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}

		go s.handleConnection(conn)
	}
}

func (s *Server) Shutdown() error {
	s.mu.RLock()
	ln := s.ln
	s.mu.RUnlock()

	if ln == nil {
		return nil
	}

	err := ln.Close()

	// quic.ErrServerClosed is expected when closing
	if err != nil && !errors.Is(err, quic.ErrServerClosed) {
		return err
	}

	return nil
}

func (s *Server) handleConnection(conn *quic.Conn) {
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

func (s *Server) handleStream(conn *quic.Conn, stream *quic.Stream) {
	defer stream.Close()

	// Limit read size to prevent DoS
	limitedReader := io.LimitReader(stream, maxMsgSize)
	buf, err := io.ReadAll(limitedReader)
	if err != nil {
		_ = conn.CloseWithError(ProtocolError, err.Error())
		return
	}

	if len(buf) < minMsgHeaderSize {
		_ = conn.CloseWithError(ProtocolError, "dns msg size too small")
		return
	}

	// Extract message length prefix
	msgLen := binary.BigEndian.Uint16(buf[:2])
	if int(msgLen) != len(buf)-2 {
		_ = conn.CloseWithError(ProtocolError, "message length mismatch")
		return
	}

	req := acquireMsg()
	defer releaseMsg(req)

	if err := req.Unpack(buf[2:]); err != nil {
		_ = conn.CloseWithError(ProtocolError, err.Error())
		return
	}

	// Generate new ID for security
	req.Id = dns.Id()

	w := &ResponseWriter{Conn: conn, Stream: stream}
	s.Handler.ServeDNS(w, req)
}
