package mock

import (
	"net"

	"github.com/miekg/dns"
)

// Writer type
type Writer struct {
	msg *dns.Msg

	localAddr  net.Addr
	remoteAddr net.Addr
}

// NewWriter return writer
func NewWriter(Net, addr string) *Writer {
	var naddr net.Addr

	if Net == "tcp" {
		naddr = &net.TCPAddr{IP: net.ParseIP(addr)}
	} else {
		naddr = &net.UDPAddr{IP: net.ParseIP(addr)}
	}

	return &Writer{
		localAddr:  naddr,
		remoteAddr: naddr,
	}
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
