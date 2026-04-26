// Package views serves per-client static answers for configured
// zones. A query whose source IP falls inside one of a view's
// CIDRs gets that view's records as the response; queries that
// don't match any view (by source IP or by name) fall through the
// chain to the regular resolution path.
//
// Views are intentionally evaluated before blocklist and resolver
// so an admin-curated answer for a specific client always wins.
// Internal sub-queries skip views entirely — they have no
// meaningful client IP and views are a client-traffic concept.
package views

import (
	"context"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
	"github.com/yl2chen/cidranger"
)

// Views is the configured set of per-CIDR static-answer views,
// evaluated in the order they appeared in cfg.Views.
type Views struct {
	views []*compiledView
}

type compiledView struct {
	zone    string
	ranger  cidranger.Ranger
	answers []dns.RR
}

// New parses cfg.Views into compiled in-memory tables. Malformed
// networks and unparseable RR strings are logged and skipped,
// matching the lenient pattern accesslist / blocklist already use
// — a typo in one entry should not knock out the rest of the
// config.
func New(cfg *config.Config) *Views {
	v := &Views{}
	for _, vc := range cfg.Views {
		cv := &compiledView{
			zone:   vc.Zone,
			ranger: cidranger.NewPCTrieRanger(),
		}
		for _, cidr := range vc.Networks {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				zlog.Error("View network CIDR parse failed", "view", vc.Zone, "cidr", cidr, "error", err.Error())
				continue
			}
			_ = cv.ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
		}
		for _, rr := range vc.Answers {
			parsed, err := dns.NewRR(rr)
			if err != nil || parsed == nil {
				msg := "nil"
				if err != nil {
					msg = err.Error()
				}
				zlog.Error("View answer parse failed", "view", vc.Zone, "answer", rr, "error", msg)
				continue
			}
			cv.answers = append(cv.answers, parsed)
		}
		v.views = append(v.views, cv)
	}
	return v
}

// (*Views).Name returns the middleware name.
func (v *Views) Name() string { return name }

// (*Views).ClientOnly excludes views from internal sub-pipelines.
// Views answer based on the originating client's IP; an internal
// sub-query has no real client and would otherwise fall through
// to whatever sentinel address the internal writer carries.
func (v *Views) ClientOnly() bool { return true }

// (*Views).ServeDNS dispatches a query to the first view whose
// source CIDR contains the client IP. If a record matches the
// query's name and type, the synthesised reply is written and the
// chain is short-circuited; otherwise the request falls through.
func (v *Views) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	if len(v.views) == 0 || ch.Writer.Internal() {
		ch.Next(ctx)
		return
	}

	clientIP := ch.Writer.RemoteIP()
	if clientIP == nil {
		ch.Next(ctx)
		return
	}

	q := ch.Request.Question[0]
	qname := dns.CanonicalName(q.Name)

	for _, cv := range v.views {
		ok, _ := cv.ranger.Contains(clientIP)
		if !ok {
			continue
		}

		// Collect exact-name matches and wildcard matches separately
		// so an exact owner can override a covering wildcard
		// (RFC 4592 §3.2). Among wildcards, only those rooted at
		// the longest matching suffix — the closest encloser per
		// RFC 4592 §2.2.1 — apply, so a "*.sub.example.lan."
		// entry wins over a covering "*.example.lan." for any
		// name under sub.example.lan.
		var exact, wild []dns.RR
		bestWildSuffix := 0
		for _, rr := range cv.answers {
			if rr.Header().Rrtype != q.Qtype {
				continue
			}
			owner := dns.CanonicalName(rr.Header().Name)
			if !nameMatches(owner, qname) {
				continue
			}
			cp := dns.Copy(rr)
			cp.Header().Name = q.Name
			if !strings.HasPrefix(owner, "*.") {
				exact = append(exact, cp)
				continue
			}
			suffixLen := len(owner) - 2 // strip leading "*."
			switch {
			case suffixLen > bestWildSuffix:
				bestWildSuffix = suffixLen
				wild = append(wild[:0], cp)
			case suffixLen == bestWildSuffix:
				wild = append(wild, cp)
			}
			// shorter-suffix wildcards lose to a more specific one
			// already collected; skip.
		}
		answers := exact
		if len(answers) == 0 {
			answers = wild
		}

		if len(answers) == 0 {
			// The view matched the client but has no answer for
			// this name/qtype combination. Fall through so the
			// resolver still answers the query — same fall-through
			// semantics the feature was requested in #360 to
			// preserve.
			break
		}

		msg := new(dns.Msg)
		msg.SetReply(ch.Request)
		msg.Authoritative = true
		msg.RecursionAvailable = true
		msg.Answer = answers
		_ = ch.Writer.WriteMsg(msg)
		ch.Cancel()
		return
	}

	ch.Next(ctx)
}

// nameMatches reports whether qname (canonical form) is covered by
// the record owner. Wildcard syntax: an owner starting with "*."
// matches any name strictly more specific than the suffix
// (RFC 4592 §2.1.1). Non-wildcard owners must match exactly.
func nameMatches(owner, qname string) bool {
	owner = dns.CanonicalName(owner)
	if !strings.HasPrefix(owner, "*.") {
		return owner == qname
	}
	suffix := owner[2:]
	if !strings.HasSuffix(qname, suffix) {
		return false
	}
	// "*.example.com." must not match "example.com." itself, and
	// the boundary just before suffix must be a label separator.
	if qname == suffix {
		return false
	}
	head := qname[:len(qname)-len(suffix)]
	return strings.HasSuffix(head, ".")
}

const name = "views"
