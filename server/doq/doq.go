package doq

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
)

var doqProtos = []string{"doq", "doq-i02", "dq", "doq-i00", "doq-i01", "doq-i11"}

const (
	minMsgHeaderSize = 14 // fixed msg header size 12 + quic prefix size 2
	ProtocolError    = 0x2
	NoError          = 0x0
)

type Server struct {
	Addr    string
	Handler dns.Handler

	ln *quic.Listener
}

func (s *Server) ListenAndServeQUIC(tlsCert, tlsKey string) error {
	cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
	if err != nil {
		return err
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   doqProtos,
	}

	quicConfig := &quic.Config{
		MaxIdleTimeout:         5 * time.Second,
		MaxStreamReceiveWindow: dns.MaxMsgSize,
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

	if err == quic.ErrServerClosed {
		return nil
	}

	return err
}

func (s *Server) handleConnection(conn quic.Connection) {
	var (
		stream quic.Stream
		buf    []byte
		err    error
	)

	for {
		stream, err = conn.AcceptStream(context.Background())
		if err != nil {
			_ = conn.CloseWithError(NoError, "")
			return
		}

		go func() {
			defer stream.Close()

			buf, err = io.ReadAll(stream)
			if err != nil {
				_ = conn.CloseWithError(ProtocolError, err.Error())
				return
			}

			if len(buf) < minMsgHeaderSize {
				_ = conn.CloseWithError(ProtocolError, "dns msg size too small")
				return
			}

			req := new(dns.Msg)
			if err := req.Unpack(buf[2:]); err != nil {
				_ = conn.CloseWithError(ProtocolError, err.Error())
				return
			}
			req.Id = dns.Id()

			w := &ResponseWriter{Conn: conn, Stream: stream}

			s.Handler.ServeDNS(w, req)
		}()
	}
}
