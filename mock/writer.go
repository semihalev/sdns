package mock

import (
	"fmt"
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
	var raddr, laddr net.Addr

	if Net == "tcp" || Net == "https" || Net == "tcp-tls" {
		laddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
		raddr, _ = net.ResolveTCPAddr("tcp", addr)
	} else {
		laddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
		raddr, _ = net.ResolveUDPAddr("udp", addr)
	}

	return &Writer{
		localAddr:  laddr,
		remoteAddr: raddr,
	}
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

// Reset func
func (w *Writer) Reset(writer dns.ResponseWriter) {
	fmt.Println("reset called")
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
