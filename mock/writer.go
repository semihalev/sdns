package mock

import (
	"net"

	"github.com/miekg/dns"
)

// Writer type
type Writer struct {
	msg *dns.Msg

	proto string

	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewWriter return writer
func NewWriter(Net, addr string) *Writer {
	w := &Writer{}

	if Net == "tcp" || Net == "https" || Net == "tcp-tls" {
		w.localAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
		w.remoteAddr, _ = net.ResolveTCPAddr("tcp", addr)
		w.proto = "tcp"
	} else {
		w.localAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
		w.remoteAddr, _ = net.ResolveUDPAddr("udp", addr)
		w.proto = "udp"
	}

	return w
}

// Rcode return message response code
func (w *Writer) Rcode() int {
	if w.msg == nil {
		return dns.RcodeServerFailure
	}

	return w.msg.Rcode
}

// Msg return current dns message
func (w *Writer) Msg() *dns.Msg {
	return w.msg
}

// Write func
func (w *Writer) Write(b []byte) (int, error) {
	w.msg = new(dns.Msg)
	err := w.msg.Unpack(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// WriteMsg func
func (w *Writer) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

// Written func
func (w *Writer) Written() bool {
	return w.msg != nil
}

// Proto func
func (w *Writer) Proto() string { return w.proto }

// Reset func
func (w *Writer) Reset(rw dns.ResponseWriter) {}

// Close func
func (w *Writer) Close() error { return nil }

// Hijack func
func (w *Writer) Hijack() {}

// LocalAddr func
func (w *Writer) LocalAddr() net.Addr { return w.localAddr }

// RemoteAddr func
func (w *Writer) RemoteAddr() net.Addr { return w.remoteAddr }

// TsigStatus func
func (w *Writer) TsigStatus() error { return nil }

// TsigTimersOnly func
func (w *Writer) TsigTimersOnly(ok bool) {}
