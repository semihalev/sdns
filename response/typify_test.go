// Copyright 2016-2020 The CoreDNS authors and contributors
// Adapted for SDNS usage by Semih Alev.

package response

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func TestTypifyNilMsg(t *testing.T) {
	var m *dns.Msg

	ty, _ := Typify(m, time.Now().UTC())
	if ty != OtherError {
		t.Errorf("Message wrongly typified, expected OtherError, got %s", ty)
	}

	ty, _ = TypeFromString("")
	if ty != NoError {
		t.Errorf("Message wrongly typified, expected NoError, got %s", ty)
	}

	ty, _ = TypeFromString("NOERROR")
	if ty != NoError {
		t.Errorf("Message wrongly typified, expected NoError, got %s", ty)
	}

	ts := ty.String()
	if ts != "NOERROR" {
		t.Errorf("Type to string wrong, expected NOERROR, got %s", ty)
	}
}

func TestTypify(t *testing.T) {
	m := new(dns.Msg)
	m.SetQuestion("miek.nl.", dns.TypeA)

	utc := time.Now().UTC()

	mt, _ := Typify(m, utc)
	if mt != NoError {
		t.Errorf("Message is wrongly typified, expected NoError, got %s", mt)
	}

	m.Opcode = dns.OpcodeUpdate
	mt, _ = Typify(m, utc)
	if mt != Update {
		t.Errorf("Message is wrongly typified, expected Update, got %s", mt)
	}

	m.Opcode = dns.OpcodeNotify
	mt, _ = Typify(m, utc)
	if mt != Meta {
		t.Errorf("Message is wrongly typified, expected Meta, got %s", mt)
	}

	m.Opcode = dns.OpcodeQuery
	m.SetQuestion("miek.nl.", dns.TypeAXFR)
	mt, _ = Typify(m, utc)
	if mt != Meta {
		t.Errorf("Message is wrongly typified, expected Meta, got %s", mt)
	}

	m.SetQuestion("miek.nl.", dns.TypeA)
	m.Ns = append(m.Ns, makeRR("nl.			3599	IN	SOA	ns1.dns.nl. hostmaster.domain-registry.nl. 2018111539 3600 600 2419200 600"))
	mt, _ = Typify(m, utc)
	if mt != NoData {
		t.Errorf("Message is wrongly typified, expected NoData, got %s", mt)
	}

	m.Rcode = dns.RcodeNameError
	mt, _ = Typify(m, utc)
	if mt != NameError {
		t.Errorf("Message is wrongly typified, expected NameError, got %s", mt)
	}

	m.Rcode = dns.RcodeServerFailure
	mt, _ = Typify(m, utc)
	if mt != OtherError {
		t.Errorf("Message is wrongly typified, expected OtherError, got %s", mt)
	}

	m.SetEdns0(4096, true)

	m.Rcode = dns.RcodeSuccess
	m.Answer = append(m.Answer, makeRR("miek.nl. 3600	IN	A	127.0.0.1"))
	mt, _ = Typify(m, utc)
	if mt != NoError {
		t.Errorf("Message is wrongly typified, expected NoError, got %s", mt)
	}

	m.Extra = append(m.Extra,
		makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20160521031301 20160421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="),
	)
	mt, _ = Typify(m, utc)
	if mt != Expired {
		t.Errorf("Message is wrongly typified, expected Expired, got %s", mt)
	}

	m.Answer = append(m.Answer,
		makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20160521031301 20160421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="),
	)
	mt, _ = Typify(m, utc)
	if mt != Expired {
		t.Errorf("Message is wrongly typified, expected Expired, got %s", mt)
	}
}

func TestTypifyDelegation(t *testing.T) {
	m := delegationMsg()
	mt, _ := Typify(m, time.Now().UTC())
	if mt != Delegation {
		t.Errorf("Message is wrongly typified, expected Delegation, got %s", mt)
	}
}

func TestTypifyRRSIG(t *testing.T) {
	utc := time.Now().UTC()

	m := delegationMsgRRSIGOK()
	if mt, _ := Typify(m, utc); mt != Delegation {
		t.Errorf("Message is wrongly typified, expected Delegation, got %s", mt)
	}

	// Still a Delegation because EDNS0 OPT DO bool is not set, so we won't check the sigs.
	m = delegationMsgRRSIGFail()
	if mt, _ := Typify(m, utc); mt != Delegation {
		t.Errorf("Message is wrongly typified, expected Delegation, got %s", mt)
	}

	m = delegationMsgRRSIGFail()
	m = addOpt(m)
	if mt, _ := Typify(m, utc); mt != Expired {
		t.Errorf("Message is wrongly typified, expected Expired, got %s", mt)
	}
}

func delegationMsg() *dns.Msg {
	return &dns.Msg{
		Ns: []dns.RR{
			makeRR("miek.nl.	3600	IN	NS	linode.atoom.net."),
			makeRR("miek.nl.	3600	IN	NS	ns-ext.nlnetlabs.nl."),
			makeRR("miek.nl.	3600	IN	NS	omval.tednet.nl."),
		},
		Extra: []dns.RR{
			makeRR("omval.tednet.nl.	3600	IN	A	185.49.141.42"),
			makeRR("omval.tednet.nl.	3600	IN	AAAA	2a04:b900:0:100::42"),
		},
	}
}

func delegationMsgRRSIGOK() *dns.Msg {
	del := delegationMsg()
	del.Ns = append(del.Ns,
		makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20170521031301 20170421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="),
	)
	return del
}

func delegationMsgRRSIGFail() *dns.Msg {
	del := delegationMsg()
	del.Ns = append(del.Ns,
		makeRR("miek.nl.		1800	IN	RRSIG	NS 8 2 1800 20160521031301 20160421031301 12051 miek.nl. PIUu3TKX/sB/N1n1E1yWxHHIcPnc2q6Wq9InShk+5ptRqChqKdZNMLDm gCq+1bQAZ7jGvn2PbwTwE65JzES7T+hEiqR5PU23DsidvZyClbZ9l0xG JtKwgzGXLtUHxp4xv/Plq+rq/7pOG61bNCxRyS7WS7i7QcCCWT1BCcv+ wZ0="),
	)
	return del
}

func addOpt(m *dns.Msg) *dns.Msg {
	return m.SetEdns0(4096, true)
}
