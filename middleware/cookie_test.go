package middleware

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cookie"
	"github.com/semihalev/sdns/internal/mock"
)

// Classifying a wire-born query's cookie is on the serving path of every
// query that sends one, and reads the request's own bytes: no allocation.
func TestCookieClassifiesWithoutAllocating(t *testing.T) {
	q := new(dns.Msg)
	q.SetQuestion("example.com.", dns.TypeA)
	q.SetEdns0(1232, false)
	q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: "0102030405060708"}}
	raw, err := q.Pack()
	if err != nil {
		t.Fatal(err)
	}
	var req Request
	if !req.ParseWire(raw, time.Now(), nil) {
		t.Fatal("eligible query refused by ParseWire")
	}
	secret := cookie.NewSecret("00112233445566778899aabbccddeeff")
	ch := NewChain(nil)
	w := mock.NewWriter("udp", "192.0.2.1:5353")
	if allocs := testing.AllocsPerRun(100, func() {
		ch.ResetWire(w, &req)
		if ch.Cookie(secret).Verdict != cookie.ClientOnly {
			t.Fatal("client cookie not classified")
		}
	}); allocs != 0 {
		t.Fatalf("classifying a wire-born cookie allocated %.0f objects", allocs)
	}
}

// Only a handshake proves a source: TCP and DoQ always, DoH when its
// transport says so, a datagram never.
func TestSourceVerified(t *testing.T) {
	for _, tc := range []struct {
		name string
		w    Transport
		want bool
	}{
		{"udp", mock.NewWriter("udp", "192.0.2.1:5353"), false},
		{"tcp", mock.NewWriter("tcp", "192.0.2.1:5353"), true},
		{"doh, unsaid", mock.NewWriter("doh", "192.0.2.1:443"), false},
		{"doh, handshake done", sourceWriter{mock.NewWriter("doh", "192.0.2.1:443"), true}, true},
		{"doh, early data", sourceWriter{mock.NewWriter("doh", "192.0.2.1:443"), false}, false},
	} {
		ch := NewChain(nil)
		ch.Reset(tc.w, new(dns.Msg))
		if got := ch.SourceVerified(); got != tc.want {
			t.Fatalf("%s: SourceVerified %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A source is proved by its transport, by a valid server cookie once
// classified, or by being loopback; a datagram with none of these is not.
func TestSourceProved(t *testing.T) {
	secret := cookie.NewSecret("00112233445566778899aabbccddeeff")
	query := func(cookieHex string) *dns.Msg {
		q := new(dns.Msg)
		q.SetQuestion("example.com.", dns.TypeA)
		q.SetEdns0(1232, false)
		if cookieHex != "" {
			q.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookieHex}}
		}
		return q
	}

	// A server cookie for this client, as a first exchange would hand it.
	first := NewChain(nil)
	first.Reset(mock.NewWriter("udp", "192.0.2.1:5353"), query("0102030405060708"))
	full, ok := secret.Reply(first.Cookie(secret))
	if !ok {
		t.Fatal("no server cookie for a client cookie")
	}
	valid := hex.EncodeToString(full[:])

	for _, tc := range []struct {
		name     string
		w        Transport
		cookie   string
		classify bool
		want     bool
	}{
		{"udp", mock.NewWriter("udp", "192.0.2.1:5353"), "", true, false},
		{"tcp", mock.NewWriter("tcp", "192.0.2.1:5353"), "", true, true},
		{"loopback udp", mock.NewWriter("udp", "127.0.0.1:5353"), "", true, true},
		{"udp, client cookie only", mock.NewWriter("udp", "192.0.2.1:5353"), "0102030405060708", true, false},
		{"udp, valid cookie", mock.NewWriter("udp", "192.0.2.1:5353"), valid, true, true},
		{"udp, valid cookie unclassified", mock.NewWriter("udp", "192.0.2.1:5353"), valid, false, false},
		{"udp, valid cookie from elsewhere", mock.NewWriter("udp", "192.0.2.2:5353"), valid, true, false},
	} {
		ch := NewChain(nil)
		ch.Reset(tc.w, query(tc.cookie))
		if tc.classify {
			ch.Cookie(secret)
		}
		if got := ch.SourceProved(); got != tc.want {
			t.Fatalf("%s: SourceProved %v, want %v", tc.name, got, tc.want)
		}
	}
}

type sourceWriter struct {
	*mock.Writer
	verified bool
}

func (w sourceWriter) SourceVerified() bool { return w.verified }
