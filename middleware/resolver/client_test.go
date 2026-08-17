package resolver

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
)

func Test_ClientTimeout(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	// A silent local listener guarantees a read timeout on any host. The
	// previous hardcoded 127.1.0.255:53 target is answered by a wildcard-bound
	// DNS server on the same machine (e.g. a live sdns), which turned this
	// timeout test into a successful live query.
	blackhole, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer func() { _ = blackhole.Close() }()

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	co.Conn, err = dialer.Dial("udp4", blackhole.LocalAddr().String())
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	_, _, err = co.Exchange(req)
	if err == nil {
		t.Errorf("expected an error, got nil")
	}
	if err := co.Close(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func Test_Client(t *testing.T) {
	// Answered from loopback. This exercises the connection's own exchange —
	// write, read, match — which a root server is not needed for, and which
	// used to make the test fail on any machine without internet.
	addr, stop := startEchoingQuestionServer(t)
	defer stop()

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeNS)
	req.SetEdns0(dnsutil.DefaultMsgSize, true)

	dialer := &net.Dialer{Deadline: time.Now().Add(2 * time.Second)}
	co := &Conn{}

	var err error
	co.Conn, err = dialer.Dial("udp4", addr)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	r, _, err := co.Exchange(req)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if r == nil {
		t.Fatalf("r is nil")
	}
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
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	defer func() { _ = co.Close() }()

	err = co.SetDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// The upstream returns a response whose question is victim.test. but the
	// outstanding request asked for attacker.test. — Exchange must surface
	// this as an error rather than handing the unrelated message back to the
	// caller (which would otherwise cache it under victim.test.).
	_, _, err = co.Exchange(req)
	if !errors.Is(err, ErrQuestion) {
		t.Errorf("error = %v, want %v", err, ErrQuestion)
	}
}

// startEchoingQuestionServer answers every query with the question it was
// asked and one NS record, which is all a connection-level exchange test
// needs from the other end.
func startEchoingQuestionServer(t *testing.T) (string, func()) {
	t.Helper()

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true
		if rr, err := dns.NewRR(". 3600 IN NS ns.test."); err == nil {
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
