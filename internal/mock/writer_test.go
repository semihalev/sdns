package mock

import (
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func Test_Writer(t *testing.T) {
	mw := NewWriter("udp", "127.0.0.1:0")

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	err := mw.WriteMsg(m)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	}
	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeSuccess) {
		t.Errorf("dns.RcodeSuccess = %v, want %v", dns.RcodeSuccess, mw.Rcode())
	}
	if mw.Msg() == nil {
		t.Fatalf("mw.Msg() is nil")
	}
	if !reflect.DeepEqual(mw.LocalAddr().String(), "127.0.0.1:53") {
		t.Errorf("'127.0.0.1:53' = %v, want %v", "127.0.0.1:53", mw.LocalAddr().String())
	}
	if !reflect.DeepEqual(mw.RemoteAddr().String(), "127.0.0.1:0") {
		t.Errorf("'127.0.0.1:0' = %v, want %v", "127.0.0.1:0", mw.RemoteAddr().String())
	}
	if mw.Close() != nil {
		t.Errorf("mw.Close() = %v, want nil", mw.Close())
	}

	mw = NewWriter("tcp", "127.0.0.255:0")
	if mw.Written() {
		t.Errorf("mw.Written() is true")
	}
	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeServerFailure) {
		t.Errorf("dns.RcodeServerFailure = %v, want %v", dns.RcodeServerFailure, mw.Rcode())
	}

	if !reflect.DeepEqual("tcp", mw.Proto()) {
		t.Errorf("mw.Proto() = %v, want %v", mw.Proto(), "tcp")
	}
	if !reflect.DeepEqual("127.0.0.255", mw.RemoteIP().String()) {
		t.Errorf("mw.RemoteIP().String() = %v, want %v", mw.RemoteIP().String(), "127.0.0.255")
	}

	_, err = mw.Write([]byte{})
	if err == nil {
		t.Errorf("expected an error, got nil")
	}

	data, err := m.Pack()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	_, err = mw.Write(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if !(mw.Written()) {
		t.Errorf("mw.Written() is false")
	}
	if !reflect.DeepEqual(mw.Rcode(), dns.RcodeSuccess) {
		t.Errorf("dns.RcodeSuccess = %v, want %v", dns.RcodeSuccess, mw.Rcode())
	}
	if !(mw.Internal()) {
		t.Errorf("mw.Internal() is false")
	}
}
