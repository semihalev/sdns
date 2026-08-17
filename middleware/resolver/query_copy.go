package resolver

import "github.com/miekg/dns"

// acquireAttemptReq builds the per-server view of a lookup's immutable
// leader request from the message pool: header by value, every section
// re-appended into the shell's own backings, records shared by
// pointer — except the OPT, which gets a private shell. PackBuffer
// writes the extended rcode into the OPT header on every pack (miekg
// msg.go, "set extended rcode unconditionally"), so concurrent attempts
// cannot share the OPT struct; its options CAN stay shared, because
// packing only reads them and the one appender — the TCP leg's
// keepalive — privatizes the whole OPT first (privatizeOPT). One small
// allocation per attempt replaces the full deep copy that priced every
// upstream fan-out at an OPT-and-options clone per server.
func acquireAttemptReq(leader *dns.Msg) *dns.Msg {
	dst := AcquireMsg()
	dst.MsgHdr = leader.MsgHdr
	dst.Compress = leader.Compress
	dst.Question = append(dst.Question[:0], leader.Question...)
	dst.Answer = append(dst.Answer[:0], leader.Answer...)
	dst.Ns = append(dst.Ns[:0], leader.Ns...)
	dst.Extra = dst.Extra[:0]
	for _, rr := range leader.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			shell := *opt
			rr = &shell
		}
		dst.Extra = append(dst.Extra, rr)
	}
	return dst
}

// privatizeOPT replaces req's OPT records with deep copies so a subsequent
// in-place OPT edit stays private to this attempt. Every OPT is covered
// because SetEDNSKeepalive appends to the LAST one (miekg's IsEdns0 scans
// backward), and stopping at the first would leave a multi-OPT decoded
// request's edit target on shared state. No-op without an OPT.
func privatizeOPT(req *dns.Msg) {
	for i, rr := range req.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			req.Extra[i] = dns.Copy(opt)
		}
	}
}
