package kubernetes

import (
	"net"

	"github.com/miekg/dns"
)

// mockResponseWriter implements middleware.ResponseWriter for testing
type mockResponseWriter struct {
	msg        *dns.Msg
	localAddr  net.Addr
	remoteAddr net.Addr
	written    bool
	rcode      int
}

func (m *mockResponseWriter) LocalAddr() net.Addr {
	if m.localAddr == nil {
		m.localAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 53}
	}
	return m.localAddr
}
func (m *mockResponseWriter) RemoteAddr() net.Addr {
	if m.remoteAddr == nil {
		m.remoteAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	}
	return m.remoteAddr
}
func (m *mockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.msg = msg
	m.written = true
	m.rcode = msg.Rcode
	return nil
}
func (m *mockResponseWriter) Write(b []byte) (int, error) {
	m.written = true
	// Try to parse the wire format
	msg := new(dns.Msg)
	if err := msg.Unpack(b); err == nil {
		m.msg = msg
		m.rcode = msg.Rcode
	}
	return len(b), nil
}
func (m *mockResponseWriter) Close() error        { return nil }
func (m *mockResponseWriter) TsigStatus() error   { return nil }
func (m *mockResponseWriter) TsigTimersOnly(bool) {}
func (m *mockResponseWriter) Hijack()             {}

// middleware.ResponseWriter methods
func (m *mockResponseWriter) Msg() *dns.Msg              { return m.msg }
func (m *mockResponseWriter) Rcode() int                 { return m.rcode }
func (m *mockResponseWriter) Written() bool              { return m.written }
func (m *mockResponseWriter) Reset(w dns.ResponseWriter) {}
func (m *mockResponseWriter) Proto() string              { return "udp" }
func (m *mockResponseWriter) RemoteIP() net.IP {
	if addr, ok := m.RemoteAddr().(*net.UDPAddr); ok {
		return addr.IP
	}
	return net.ParseIP("127.0.0.1")
}
func (m *mockResponseWriter) Internal() bool { return false }
