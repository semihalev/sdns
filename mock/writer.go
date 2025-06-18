package mock

import (
	"net"

	"github.com/miekg/dns"
)

// Writer type.
type Writer struct {
	msg *dns.Msg

	proto string

	localAddr  net.Addr
	remoteAddr net.Addr

	remoteip net.IP

	internal bool
}

// NewWriter return writer.
func NewWriter(proto, addr string) *Writer {
	w := &Writer{}

	switch proto {
	case "tcp", "doh":
		w.localAddr = &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
		w.remoteAddr, _ = net.ResolveTCPAddr("tcp", addr)
		w.remoteip = w.remoteAddr.(*net.TCPAddr).IP

	case "udp":
		w.localAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
		w.remoteAddr, _ = net.ResolveUDPAddr("udp", addr)
		w.remoteip = w.remoteAddr.(*net.UDPAddr).IP
	}

	w.internal = w.RemoteAddr().String() == "127.0.0.255:0"

	w.proto = proto

	return w
}

// (*Writer).Rcode rcode return message response code.
func (w *Writer) Rcode() int {
	if w.msg == nil {
		return dns.RcodeServerFailure
	}

	return w.msg.Rcode
}

// (*Writer).Msg msg return current dns message.
func (w *Writer) Msg() *dns.Msg {
	return w.msg
}

// (*Writer).Write write func.
func (w *Writer) Write(b []byte) (int, error) {
	w.msg = new(dns.Msg)
	err := w.msg.Unpack(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// (*Writer).WriteMsg writeMsg func.
func (w *Writer) WriteMsg(msg *dns.Msg) error {
	w.msg = msg
	return nil
}

// (*Writer).Written written func.
func (w *Writer) Written() bool {
	return w.msg != nil
}

// (*Writer).RemoteIP remoteIP func.
func (w *Writer) RemoteIP() net.IP { return w.remoteip }

// (*Writer).Proto proto func.
func (w *Writer) Proto() string { return w.proto }

// (*Writer).Reset reset func.
func (w *Writer) Reset(rw dns.ResponseWriter) {}

// (*Writer).Close close func.
func (w *Writer) Close() error { return nil }

// (*Writer).Hijack hijack func.
func (w *Writer) Hijack() {}

// (*Writer).LocalAddr localAddr func.
func (w *Writer) LocalAddr() net.Addr { return w.localAddr }

// (*Writer).RemoteAddr remoteAddr func.
func (w *Writer) RemoteAddr() net.Addr { return w.remoteAddr }

// (*Writer).TsigStatus tsigStatus func.
func (w *Writer) TsigStatus() error { return nil }

// (*Writer).TsigTimersOnly tsigTimersOnly func.
func (w *Writer) TsigTimersOnly(ok bool) {}

// (*Writer).Internal internal func.
func (w *Writer) Internal() bool { return w.internal }
