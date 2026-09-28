package server

import (
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/wire"
)

// cookieQuery packs a query with no question (RFC 7873 §5.4), carrying an
// OPT with cookie (hex) when withOPT; an empty cookie sends none.
func cookieQuery(t *testing.T, withOPT bool, cookie string) []byte {
	t.Helper()
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	if withOPT {
		m.SetEdns0(1232, false)
		if cookie != "" {
			m.IsEdns0().Option = []dns.EDNS0{&dns.EDNS0_COOKIE{Code: dns.EDNS0COOKIE, Cookie: cookie}}
		}
	}
	raw, err := m.Pack()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// serveCookieQuery sends raw through the server's ingress from the job's
// address and returns the reply, nil when the server wrote none.
func serveCookieQuery(t *testing.T, s *Server, job *strictTestJob, raw []byte) *dns.Msg {
	t.Helper()
	job.wrote = job.wrote[:0]
	if !s.ServeRaw(job, raw, time.Now()) {
		t.Fatal("packet not handled")
	}
	if len(job.wrote) == 0 {
		return nil
	}
	reply := new(dns.Msg)
	if err := reply.Unpack(job.wrote); err != nil {
		t.Fatalf("reply unpack: %v", err)
	}
	return reply
}

func replyCookie(m *dns.Msg) string {
	if opt := m.IsEdns0(); opt != nil {
		for _, o := range opt.Option {
			if c, ok := o.(*dns.EDNS0_COOKIE); ok {
				return c.Cookie
			}
		}
	}
	return ""
}

// A query with no question and a COOKIE option asks for a server cookie
// (RFC 7873 §5.4). Through the whole default chain: a client cookie alone,
// or a valid server cookie, is NOERROR with no question and a server
// cookie; a server cookie that does not verify is BADCOOKIE with a fresh
// one; without a COOKIE, or with a malformed one, it is FORMERR. None of
// them reaches the resolver.
func TestQueryForAServerCookie(t *testing.T) {
	var resolved int
	s := newHitChainServerWith(t, func(req *dns.Msg) *dns.Msg {
		resolved++
		return stubAnswer(req)
	})
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 50), Port: 4242}}
	const client = "0102030405060708"

	first := serveCookieQuery(t, s, job, cookieQuery(t, true, client))
	if first == nil || first.Rcode != dns.RcodeSuccess || len(first.Question) != 0 || len(first.Answer) != 0 {
		t.Fatalf("client cookie alone: %v, want NOERROR with no question and no answer", first)
	}
	learned := replyCookie(first)
	if len(learned) != 48 || learned[:16] != client {
		t.Fatalf("client cookie alone: reply cookie %q, want a server cookie for %s", learned, client)
	}

	if got := serveCookieQuery(t, s, job, cookieQuery(t, true, learned)); got == nil ||
		got.Rcode != dns.RcodeSuccess || replyCookie(got) != learned {
		t.Fatalf("valid server cookie: %v, want NOERROR echoing %s", got, learned)
	}

	forged, _ := hex.DecodeString(learned)
	forged[len(forged)-1] ^= 1
	bad := serveCookieQuery(t, s, job, cookieQuery(t, true, hex.EncodeToString(forged)))
	if bad == nil || bad.Rcode != dns.RcodeBadCookie {
		t.Fatalf("server cookie that does not verify: %v, want BADCOOKIE", bad)
	}
	if c := replyCookie(bad); len(c) != 48 || c[:16] != client || c == hex.EncodeToString(forged) {
		t.Fatalf("BADCOOKIE carries cookie %q, want a fresh server cookie for %s", c, client)
	}

	for _, tc := range []struct {
		name    string
		withOPT bool
		cookie  string
	}{
		{"no OPT", false, ""},
		{"an OPT without a COOKIE", true, ""},
		{"a malformed COOKIE", true, "0102030405"},
	} {
		if got := serveCookieQuery(t, s, job, cookieQuery(t, tc.withOPT, tc.cookie)); got == nil || got.Rcode != dns.RcodeFormatError {
			t.Fatalf("%s: %v, want FORMERR", tc.name, got)
		}
	}
	if resolved != 0 {
		t.Fatalf("a query with no question reached the resolver %d times", resolved)
	}
}

// A query for a server cookie takes the access and rate controls like any
// other: refused silently to an address the access list denies, and
// charged against the client's quota.
func TestQueryForAServerCookieKeepsTheControls(t *testing.T) {
	denied := newHitChainServerConfigured(t, nil, func(c *config.Config) { c.AccessList = []string{"10.0.0.0/8"} })
	job := &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 51), Port: 4242}}
	if got := serveCookieQuery(t, denied, job, cookieQuery(t, true, "0102030405060708")); got != nil {
		t.Fatalf("an address the access list denies was answered: %v", got)
	}

	limited := newHitChainServerConfigured(t, nil, func(c *config.Config) { c.ClientRateLimit = 1 })
	job = &strictTestJob{remote: net.UDPAddr{IP: net.IPv4(203, 0, 113, 52), Port: 4242}}
	raw := cookieQuery(t, true, "0102030405060708")
	if got := serveCookieQuery(t, limited, job, raw); got == nil || got.Rcode != dns.RcodeSuccess {
		t.Fatalf("within quota: %v, want NOERROR", got)
	}
	if got := serveCookieQuery(t, limited, job, raw); got == nil || got.Rcode != dns.RcodeBadCookie {
		t.Fatalf("over quota, challenged: %v, want BADCOOKIE", got)
	}
	if got := serveCookieQuery(t, limited, job, raw); got != nil {
		t.Fatalf("over quota past the challenge budget: %v, want dropped", got)
	}
}

// The engines' header gate lets a question-less query through only when
// its additional section can carry the OPT the decoded entry looks for.
func TestAcceptHeaderQuestionCount(t *testing.T) {
	for _, tc := range []struct {
		qd, ar uint16
		want   acceptVerdict
	}{
		{1, 0, acceptOK},
		{0, 1, acceptOK},
		{0, 0, acceptFormatError},
		{2, 1, acceptFormatError},
	} {
		if got := acceptHeader(wire.Header{QDCount: tc.qd, ARCount: tc.ar}); got != tc.want {
			t.Fatalf("QDCOUNT=%d ARCOUNT=%d: verdict %d, want %d", tc.qd, tc.ar, got, tc.want)
		}
	}
}
