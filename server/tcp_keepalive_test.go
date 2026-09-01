package server

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware/edns"
)

// The RFC 7828 advertisement is a promise about this engine's behaviour:
// the client may keep the connection idle for as long as the option
// says. The edns layer cannot import this package to read tcpIdleWait,
// so the two constants are pinned to each other here, a server that
// advertises longer than it holds hangs up on clients it told to stay.
func TestKeepaliveAdvertisesTheRealIdleTimeout(t *testing.T) {
	if edns.TCPKeepaliveTimeout != tcpIdleWait {
		t.Fatalf("edns advertises %v, the engine enforces %v",
			edns.TCPKeepaliveTimeout, tcpIdleWait)
	}
}

// tcpStrictTestJob is strictTestJob's stream twin: a TCP remote, so the
// middleware sees proto "tcp" exactly as it does for the owned TCP and
// DoT transports.
type tcpStrictTestJob struct {
	strictTestJob
	remoteTCP net.TCPAddr
}

func (j *tcpStrictTestJob) RemoteAddr() net.Addr { return &j.remoteTCP }
func (j *tcpStrictTestJob) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53}
}

func packKeepaliveQuery(t *testing.T, name string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeA)
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(1232)
	opt.Option = append(opt.Option, &dns.EDNS0_TCP_KEEPALIVE{Code: dns.EDNS0TCPKEEPALIVE})
	m.Extra = append(m.Extra, opt)
	raw, err := m.Pack()
	if err != nil {
		t.Fatalf("pack: %v", err)
	}
	return raw
}

func keepaliveIn(t *testing.T, wrote []byte) (uint16, bool) {
	t.Helper()
	r := new(dns.Msg)
	if err := r.Unpack(wrote); err != nil {
		t.Fatalf("reply unpack: %v", err)
	}
	opt := r.IsEdns0()
	if opt == nil {
		return 0, false
	}
	for _, o := range opt.Option {
		if ka, ok := o.(*dns.EDNS0_TCP_KEEPALIVE); ok {
			return ka.Timeout, true
		}
	}
	return 0, false
}

// TestKeepaliveFollowsTheTransport is RFC 7828 through the full default
// chain: a stream client that sent edns-tcp-keepalive is told the idle
// timeout, a stream client that did not ask is not, and a datagram
// client never is, the option is forbidden over UDP in both directions,
// and ignoring it there is what the RFC asks of a server.
func TestKeepaliveFollowsTheTransport(t *testing.T) {
	s := newRawTestServer(t)
	want := uint16(edns.TCPKeepaliveTimeout / (100 * time.Millisecond))

	t.Run("stream client that asked", func(t *testing.T) {
		job := &tcpStrictTestJob{remoteTCP: net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4711}}
		if !s.ServeRaw(job, packKeepaliveQuery(t, "ka.example."), time.Now()) {
			t.Fatal("eligible packet not handled")
		}
		timeout, ok := keepaliveIn(t, job.wrote)
		if !ok {
			t.Fatal("no edns-tcp-keepalive in the response to a stream client that sent it")
		}
		if timeout != want {
			t.Fatalf("advertised %d units, want %d", timeout, want)
		}
	})

	t.Run("stream client that did not ask", func(t *testing.T) {
		job := &tcpStrictTestJob{remoteTCP: net.TCPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4712}}
		if !s.ServeRaw(job, packRawQuery(t, "plain.example.", true), time.Now()) {
			t.Fatal("eligible packet not handled")
		}
		if _, ok := keepaliveIn(t, job.wrote); ok {
			t.Fatal("keepalive advertised to a client that never sent the option")
		}
	})

	t.Run("datagram client is ignored, not told", func(t *testing.T) {
		job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 9), Port: 4713}}
		if !s.ServeRaw(job, packKeepaliveQuery(t, "udp-ka.example."), time.Now()) {
			t.Fatal("eligible packet not handled")
		}
		if _, ok := keepaliveIn(t, job.wrote); ok {
			t.Fatal("edns-tcp-keepalive in a UDP response; RFC 7828 forbids it " +
				"in both directions over UDP")
		}
		r := new(dns.Msg)
		if err := r.Unpack(job.wrote); err != nil {
			t.Fatal(err)
		}
		if r.Rcode != dns.RcodeSuccess {
			t.Fatalf("rcode = %v; the option is ignored over UDP, not an error", r.Rcode)
		}
	})
}
