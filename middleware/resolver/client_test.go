package resolver

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/util"
	"github.com/stretchr/testify/assert"
)

func Test_ClientTimeout(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(util.DefaultMsgSize, true)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp4", "127.1.0.255:53")
	assert.NoError(t, err)

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	assert.NoError(t, err)

	_, _, err = co.Exchange(req)
	assert.Error(t, err)
	assert.NoError(t, co.Close())
}

func Test_Client(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(util.DefaultMsgSize, true)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp4", "198.41.0.4:53")
	assert.NoError(t, err)

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	assert.NoError(t, err)

	r, _, err := co.Exchange(req)
	assert.NoError(t, err)
	assert.NotNil(t, r)
}

// startMismatchedQuestionServer returns a UDP server that always replies with
// a fixed question section (victim.test. A) regardless of what was asked. It
// models a malicious upstream attempting cache poisoning via the response's
// question section (issue #469).
func startMismatchedQuestionServer(t *testing.T) (addr string, stop func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Question = []dns.Question{{Name: "victim.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET}}
		if rr, err := dns.NewRR("victim.test. 60 IN A 6.6.6.6"); err == nil {
			m.Answer = []dns.RR{rr}
		}
		_ = w.WriteMsg(m)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	s := &dns.Server{Net: "udp", Handler: mux, PacketConn: pc}
	go func() { _ = s.ActivateAndServe() }()
	return pc.LocalAddr().String(), func() { _ = s.Shutdown() }
}

func Test_Client_RejectsMismatchedQuestion(t *testing.T) {
	addr, stop := startMismatchedQuestionServer(t)
	defer stop()

	req := new(dns.Msg)
	req.SetQuestion("attacker.test.", dns.TypeA)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp", addr)
	assert.NoError(t, err)
	defer func() { _ = co.Close() }()

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	assert.NoError(t, err)

	// The upstream returns a response whose question is victim.test. but the
	// outstanding request asked for attacker.test. — Exchange must surface
	// this as an error rather than handing the unrelated message back to the
	// caller (which would otherwise cache it under victim.test.).
	_, _, err = co.Exchange(req)
	assert.ErrorIs(t, err, ErrQuestion)
}
