// Package dnsutil provides DNS protocol utilities for SDNS.
package dnsutil

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/netip"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/ecs"
)

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

// SetEdns0 returns replaced or new opt rr and if request has do.
//
// The function inspects the client's OPT record to harvest NSID / COOKIE
// signalling, strips every option before forwarding (RFC 7871 §11 privacy
// guidance is the default), and normalises the UDP size. Inspection uses
// typed pointer assertions so we avoid the allocating option.String()
// path, and the stripping reuses opt.Option's backing storage via
// opt.Option = nil rather than allocating an empty slice.
//
// When `policy` is non-nil, enabled, and allows the supplied client, the
// client's EDNS Client Subnet option (RFC 7871) is preserved on the
// outgoing OPT instead of stripped — clamped to the policy's source-
// prefix ceiling. Every other client-supplied option is still dropped.
// A nil policy or an empty client address means strip everything, which
// matches SDNS's historical behaviour and the privacy-first default.
func SetEdns0(req *dns.Msg, policy *ecs.Policy, client netip.Addr) (*dns.OPT, int, string, bool, bool) {
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

		var clientSubnet *dns.EDNS0_SUBNET
		for _, option := range opt.Option {
			switch v := option.(type) {
			case *dns.EDNS0_COOKIE:
				// Client cookie is the first 8 bytes (16 hex chars).
				if len(v.Cookie) >= 16 {
					cookie = v.Cookie[:16]
				}
			case *dns.EDNS0_NSID:
				nsid = true
			case *dns.EDNS0_SUBNET:
				// Capture for possible forwarding after the loop;
				// dropped along with every other option if policy
				// is nil / disabled / doesn't allow this client.
				clientSubnet = v
			}
		}

		// Drop every client-provided option from the forwarded OPT.
		// Nil-ing is cheaper than allocating a new empty slice and lets
		// the old backing array be GC'd with the request.
		opt.Option = nil

		// If the policy allows ECS forwarding for this client, put a
		// clamped copy of the client's option back on. Clamp() handles
		// source-prefix ceiling, address truncation, and family sanity;
		// a nil return means the option was unusable and we keep the
		// strip.
		if policy.Allows(client) && clientSubnet != nil {
			if forwarded := policy.Clamp(clientSubnet); forwarded != nil {
				opt.Option = append(opt.Option, forwarded)
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

// GenerateServerCookie return generated edns server cookie.
func GenerateServerCookie(secret, remoteip, cookie string) string {
	scookie := sha256.New()

	_, _ = scookie.Write([]byte(remoteip))
	_, _ = scookie.Write([]byte(cookie))
	_, _ = scookie.Write([]byte(secret))

	return cookie + hex.EncodeToString(scookie.Sum(nil))
}

// ClearOPT removes every OPT record from msg.Extra in place. No copy is
// made when the Extra section has no OPT (the common case for responses
// synthesised without EDNS).
func ClearOPT(msg *dns.Msg) *dns.Msg {
	msg.Extra = filterOut(msg.Extra, isOPT)
	return msg
}

// ClearDNSSEC removes RRSIG, NSEC and NSEC3 records from Answer and Ns
// sections in place. Short-circuits when the sections already hold
// nothing to strip (typical for non-DNSSEC responses), and reuses the
// slice backing array when a filter is actually needed.
func ClearDNSSEC(msg *dns.Msg) *dns.Msg {
	// An explicit RRSIG query must retain its RRSIG answers.
	if len(msg.Question) > 0 && msg.Question[0].Qtype == dns.TypeRRSIG {
		return msg
	}

	msg.Answer = filterOut(msg.Answer, isDNSSEC)
	msg.Ns = filterOut(msg.Ns, isDNSSEC)
	return msg
}

// filterOut returns a slice that contains every RR from rrs for which
// drop returns false. When nothing needs dropping the input is returned
// unchanged (zero allocation, hot path for non-DNSSEC responses). When
// a drop is required a new slice is returned so the caller's backing
// array is never mutated — the incoming Msg may share its Answer/Ns
// storage with a cache entry (see middleware/cache.NewCacheEntryWithKey)
// and in-place edits would corrupt the cache.
func filterOut(rrs []dns.RR, drop func(dns.RR) bool) []dns.RR {
	firstDrop := -1
	for i, rr := range rrs {
		if drop(rr) {
			firstDrop = i
			break
		}
	}
	if firstDrop == -1 {
		return rrs
	}

	kept := make([]dns.RR, firstDrop, len(rrs)-1)
	copy(kept, rrs[:firstDrop])
	for _, rr := range rrs[firstDrop+1:] {
		if drop(rr) {
			continue
		}
		kept = append(kept, rr)
	}
	return kept
}

func isOPT(rr dns.RR) bool {
	_, ok := rr.(*dns.OPT)
	return ok
}

func isDNSSEC(rr dns.RR) bool {
	switch rr.(type) {
	case *dns.RRSIG, *dns.NSEC, *dns.NSEC3:
		return true
	}
	return false
}

// Exchange exchange dns request with TCP fallback.
func Exchange(ctx context.Context, req *dns.Msg, addr string, net string, client *dns.Client) (*dns.Msg, error) {
	localClient := dns.Client{Net: net}
	if client != nil {
		// Copy to avoid mutating the caller's client (e.g. when we retry over TCP).
		localClient = *client
		localClient.Net = net
	}

	resp, _, err := localClient.ExchangeContext(ctx, req, addr)

	if err == nil && resp.Truncated && net == "udp" {
		return Exchange(ctx, req, addr, "tcp", client)
	}

	return resp, err
}

// NotSupported response to writer an empty notimplemented message.
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
	// DefaultMsgSize EDNS0 message size.
	DefaultMsgSize = 1232
)
