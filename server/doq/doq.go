package doq

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/semihalev/log"
)

var doqProtos = []string{"doq", "doq-i02", "dq", "doq-i00", "doq-i01", "doq-i11"}

type Server struct {
	Addr    string
	Handler dns.Handler
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

	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			log.Error("DNS listener failed", "net", "doq", "error", err.Error())
			break
		}

		go s.handleConnection(conn)
	}

	return nil
}

func (s *Server) handleConnection(conn quic.Connection) {
	var (
		stream quic.Stream
		buf    []byte
		err    error
	)

	stream, err = conn.AcceptStream(context.Background())
	if err != nil {
		_ = conn.CloseWithError(0x1, err.Error())
		return
	}

	defer stream.Close()

	buf, err = io.ReadAll(stream)
	if err != nil {
		_ = conn.CloseWithError(0x1, err.Error())
		return
	}

	req := new(dns.Msg)
	if err := req.Unpack(buf[2:]); err != nil {
		_ = conn.CloseWithError(0x1, err.Error())
		return
	}
	req.Id = dns.Id()

	w := &ResponseWriter{Conn: conn, Stream: stream}

	s.Handler.ServeDNS(w, req)
}
