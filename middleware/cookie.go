package middleware

import (
	"encoding/hex"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/cookie"
)

// SourceVerified reports whether the transport itself proved the client's
// source address: a TCP handshake (TCP, DoT, DoH over HTTP/1 and HTTP/2),
// or a QUIC handshake completed before the query was taken (DoQ, and DoH3
// when the transport says so). A datagram, or DoH3 early data, proves
// nothing; there only a valid server cookie does.
func (ch *Chain) SourceVerified() bool { return ch.verified }

// Cookie returns the request's COOKIE classification under s, made on the
// first call and kept for the rest of the request, its replay included,
// so every layer that asks sees the same verdict and a cookie is verified
// once. It must first be asked before the edns layer strips the client's
// options from a decoded request.
func (ch *Chain) Cookie(s cookie.Secret) *cookie.State {
	if !ch.cookieSet {
		ch.cookieSet = true
		if r := ch.Request; r != nil && r.wireBorn() {
			ch.classifyCookie(s, r.CookieEcho())
		} else {
			var buf [cookieOptionMax + 1]byte
			ch.classifyCookie(s, ch.msgCookieOption(buf[:0]))
		}
	}
	return &ch.cookie
}

func (ch *Chain) classifyCookie(s cookie.Secret, opt []byte) {
	if opt == nil {
		// Nothing else in the state is read for a query without one.
		ch.cookie.Verdict = cookie.None
		return
	}
	addr, _ := netip.AddrFromSlice(ch.Writer.RemoteIP())
	now := uint32(time.Now().Unix()) //nolint:gosec // a cookie timestamp is the epoch second modulo 2^32 (RFC 9018 §4.3)
	ch.cookie = s.Classify(opt, addr, now)
}

// cookieOptionMax is the longest COOKIE option RFC 7873 §5.2.2 admits.
const cookieOptionMax = 40

// msgCookieOption returns a decoded request's first COOKIE option, nil
// when it has none, decoded into buf; one too long for it comes back one
// byte over the limit, malformed either way.
func (ch *Chain) msgCookieOption(buf []byte) []byte {
	r := ch.Request
	if r == nil || r.msg == nil {
		return nil
	}
	opt := r.msg.IsEdns0()
	if opt == nil {
		return nil
	}
	for _, o := range opt.Option {
		c, ok := o.(*dns.EDNS0_COOKIE)
		if !ok {
			continue
		}
		if len(c.Cookie) > 2*cookieOptionMax {
			return buf[:cookieOptionMax+1]
		}
		b, err := hex.AppendDecode(buf, []byte(c.Cookie))
		if err != nil {
			return buf[:cookieOptionMax+1]
		}
		return b
	}
	return nil
}

// ChallengeCookie marks the query for a BADCOOKIE reply in place of an
// answer: the rate limiter's answer to a client over its quota that sent a
// cookie it can prove itself with. The edns layer writes the reply, after
// its own checks, so a malformed query still draws its FORMERR or BADVERS.
func (ch *Chain) ChallengeCookie() { ch.challenge = true }

// CookieChallenged reports whether the query is marked for BADCOOKIE.
func (ch *Chain) CookieChallenged() bool { return ch.challenge }

// Carry is what an inline pass hands the replay that finishes its query:
// the facts made once per request.
type Carry struct {
	cookie    cookie.State
	cookieSet bool
}

// Carry returns the facts this serve made once, for the replay.
func (ch *Chain) Carry() Carry { return Carry{cookie: ch.cookie, cookieSet: ch.cookieSet} }

// Restore gives a replay the facts its inline pass made; call it after
// ResetWire and SetReplay.
func (ch *Chain) Restore(c Carry) { ch.cookie, ch.cookieSet = c.cookie, c.cookieSet }
