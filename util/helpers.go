// Package util provides DNS protocol utilities for SDNS.
package util

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/mock"
)

var chainPool sync.Pool

func init() {
	chainPool.New = func() interface{} {
		return middleware.NewChain(middleware.Handlers())
	}
}

// SetRcode returns message specified with rcode.
func SetRcode(req *dns.Msg, rcode int, do bool) *dns.Msg {
	m := new(dns.Msg)
	m.Extra = req.Extra
	m.SetRcode(req, rcode)
	m.RecursionAvailable = true
	m.RecursionDesired = true

	if opt := m.IsEdns0(); opt != nil {
		opt.SetDo(do)
	}

	return m
}

// SetEdns0 returns replaced or new opt rr and if request has do
func SetEdns0(req *dns.Msg) (*dns.OPT, int, string, bool, bool) {
	do, nsid := false, false
	opt := req.IsEdns0()
	size := DefaultMsgSize
	cookie := ""

	if opt != nil {
		size = int(opt.UDPSize())
		if size < dns.MinMsgSize {
			size = dns.MinMsgSize
		}

		if size > DefaultMsgSize {
			size = DefaultMsgSize
		}

		opt.SetUDPSize(DefaultMsgSize)

		ops := opt.Option

		opt.Option = []dns.EDNS0{}

		for _, option := range ops {
			switch option.Option() {
			//TODO (semihalev): is this broken privacy???
			case dns.EDNS0SUBNET:
				//opt.Option = append(opt.Option, option)
			case dns.EDNS0COOKIE:
				if len(option.String()) >= 16 {
					cookie = option.String()[:16]
				}
			case dns.EDNS0NSID:
				nsid = true
			}
		}

		if opt.Version() != 0 {
			return opt, size, cookie, nsid, false
		}

		do = opt.Do()

		opt.Header().Ttl = 0
		opt.SetDo()
	} else {
		opt = new(dns.OPT)
		opt.Hdr.Name = "."
		opt.Hdr.Rrtype = dns.TypeOPT
		opt.SetUDPSize(DefaultMsgSize)
		opt.SetDo()

		req.Extra = append(req.Extra, opt)
	}

	return opt, size, cookie, nsid, do
}

// GenerateServerCookie return generated edns server cookie
func GenerateServerCookie(secret, remoteip, cookie string) string {
	scookie := sha256.New()

	_, _ = scookie.Write([]byte(remoteip))
	_, _ = scookie.Write([]byte(cookie))
	_, _ = scookie.Write([]byte(secret))

	return cookie + hex.EncodeToString(scookie.Sum(nil))
}

// ClearOPT returns cleared opt message
func ClearOPT(msg *dns.Msg) *dns.Msg {
	extra := make([]dns.RR, len(msg.Extra))
	copy(extra, msg.Extra)

	msg.Extra = []dns.RR{}

	for _, rr := range extra {
		switch rr.(type) {
		case *dns.OPT:
			continue
		default:
			msg.Extra = append(msg.Extra, rr)
		}
	}

	return msg
}

// ClearDNSSEC returns cleared RRSIG and NSECx message
func ClearDNSSEC(msg *dns.Msg) *dns.Msg {
	// we shouldn't clear RRSIG questions
	if len(msg.Question) > 0 {
		if msg.Question[0].Qtype == dns.TypeRRSIG {
			return msg
		}
	}

	var answer, ns []dns.RR

	answer = append(answer, msg.Answer...)
	msg.Answer = []dns.RR{}

	for _, rr := range answer {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC3, *dns.NSEC:
			continue
		default:
			msg.Answer = append(msg.Answer, rr)
		}
	}

	ns = append(ns, msg.Ns...)
	msg.Ns = []dns.RR{}

	for _, rr := range ns {
		switch rr.(type) {
		case *dns.RRSIG, *dns.NSEC3, *dns.NSEC:
			continue
		default:
			msg.Ns = append(msg.Ns, rr)
		}
	}

	return msg
}

// Exchange exchange dns request with TCP fallback
func Exchange(ctx context.Context, req *dns.Msg, addr string, net string) (*dns.Msg, error) {
	client := dns.Client{Net: net}
	resp, _, err := client.ExchangeContext(ctx, req, addr)

	if err == nil && resp.Truncated && net == "udp" {
		return Exchange(ctx, req, addr, "tcp")
	}

	return resp, err
}

// ExchangeInternal exchange dns request internal
func ExchangeInternal(ctx context.Context, r *dns.Msg) (*dns.Msg, error) {
	w := mock.NewWriter("tcp", "127.0.0.255:0")

	ch := chainPool.Get().(*middleware.Chain)
	defer chainPool.Put(ch)

	ch.Reset(w, r)

	ch.Next(ctx)

	if !w.Written() {
		return nil, errors.New("no replied any message")
	}

	return w.Msg(), nil
}

// ParsePurgeQuestion can parse query for purge questions
func ParsePurgeQuestion(req *dns.Msg) (qname string, qtype uint16, ok bool) {
	if len(req.Question) == 0 {
		return
	}

	bstr := strings.TrimSuffix(req.Question[0].Name, ".")

	nbytes, err := base64.StdEncoding.DecodeString(bstr)
	if err != nil {
		return
	}

	q := strings.Split(string(nbytes), ":")
	if len(q) != 2 {
		return
	}

	if qtype, ok = dns.StringToType[q[0]]; !ok {
		return
	}

	return q[1], qtype, true
}

// NotSupported response to writer a empty notimplemented message
func NotSupported(w dns.ResponseWriter, req *dns.Msg) error {
	return w.WriteMsg(&dns.Msg{
		MsgHdr: dns.MsgHdr{
			Rcode:             dns.RcodeNotImplemented,
			Id:                req.Id,
			Opcode:            req.Opcode,
			Response:          true,
			RecursionDesired:  true,
			AuthenticatedData: true,
		},
	})
}

const (
	// DefaultMsgSize EDNS0 message size
	DefaultMsgSize = 1232
)
