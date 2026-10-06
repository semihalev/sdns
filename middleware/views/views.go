// Package views serves static answers from the first client-matching view.
// Overlay mode matches name and type; opt-in authoritative-owner mode also
// answers missing types at selected IN owners. Other queries fall through.
// Views run before downstream policy and resolution; internal queries skip
// them because they have no originating client address.
package views

import (
	"context"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/dnsname"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/ipset"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/zlog/v2"
)

// Views is the configured set of per-CIDR static-answer views,
// evaluated in the order they appeared in cfg.Views.
type Views struct {
	views []*compiledView
}

type compiledView struct {
	zone     string
	mode     string
	networks *ipset.Set
	answers  []dns.RR
}

// New parses cfg.Views into compiled in-memory tables. Malformed
// networks and unparseable RR strings are logged and skipped,
// matching the lenient pattern accesslist / blocklist already use,
// a typo in one entry should not knock out the rest of the
// config.
func New(cfg *config.Config) *Views {
	v := &Views{}
	for _, vc := range cfg.Views {
		networks, bad := ipset.New(vc.Networks)
		for _, entry := range bad {
			zlog.Error("View network CIDR parse failed", "view", vc.Zone, "cidr", entry.CIDR, "error", entry.Err.Error())
		}
		cv := &compiledView{
			zone:     vc.Zone,
			mode:     vc.Mode,
			networks: networks,
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

// ServeDNS consults only the first client-matching view. Overlay answers
// matching records; authoritative-owner also answers missing types at a
// selected IN owner. Other requests fall through.
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

	ctx, req := ch.Materialize(ctx)
	if req == nil {
		return
	}

	q := req.Question[0]

	for _, cv := range v.views {
		if !cv.networks.ContainsIP(clientIP) {
			continue
		}

		if cv.mode == "authoritative-owner" {
			if q.Qclass != dns.ClassINET || dnsutil.DeclinedQtype(q.Qtype) {
				break
			}
			answers, found := cv.ownerAnswers(q)
			if !found {
				break
			}
			writeReply(ch, req, answers)
			return
		}

		qname := dns.CanonicalName(q.Name)
		// Collect exact-name matches and wildcard matches separately
		// so an exact owner can override a covering wildcard
		// (RFC 4592 §3.2). Among wildcards, only those rooted at
		// the longest matching suffix, the closest encloser per
		// RFC 4592 §2.2.1, apply, so a "*.sub.example.lan."
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
			// resolver still answers the query, same fall-through
			// semantics the feature was requested in #360 to
			// preserve.
			break
		}

		writeReply(ch, req, answers)
		return
	}

	ch.Next(ctx)
}

// ownerAnswers selects an IN owner before considering the question's type.
// A selected owner without that type or a CNAME still answers locally.
func (cv *compiledView) ownerAnswers(q dns.Question) ([]dns.RR, bool) {
	// Presentation spelling is not DNS identity: \097lias and alias name the
	// same owner. Compare decoded octets with ASCII case folding when selecting
	// an owner and collecting its RRset.
	qLabels := dns.CountLabel(q.Name)
	selected := ""
	bestSuffix := -1
	for _, rr := range cv.answers {
		if rr.Header().Class != dns.ClassINET {
			continue
		}
		owner := rr.Header().Name
		if dnsname.CanonicalCompare(owner, q.Name) == 0 {
			selected = owner
			break
		}
		if suffixLabels, matched := ownerWildcardMatch(owner, q.Name, qLabels); matched && suffixLabels > bestSuffix {
			selected = owner
			bestSuffix = suffixLabels
		}
	}
	if selected == "" {
		return nil, false
	}
	var answers, cnames []dns.RR
	for _, rr := range cv.answers {
		if rr.Header().Class != dns.ClassINET || dnsname.CanonicalCompare(rr.Header().Name, selected) != 0 {
			continue
		}
		if rr.Header().Rrtype != q.Qtype && rr.Header().Rrtype != dns.TypeCNAME {
			continue
		}
		cp := dns.Copy(rr)
		cp.Header().Name = q.Name
		if rr.Header().Rrtype == q.Qtype {
			answers = append(answers, cp)
		} else {
			cnames = append(cnames, cp)
		}
	}
	if len(answers) == 0 {
		answers = cnames
	}
	return answers, true
}

// ownerWildcardMatch reports a wildcard match and its suffix's label count.
// A wildcard's first label decodes to "*". Match only at real label
// boundaries: an escaped dot belongs to its label. The query must have
// more labels than the suffix, and specificity is measured in labels,
// so escape spelling cannot change precedence.
func ownerWildcardMatch(owner, qname string, qLabels int) (suffixLabels int, matched bool) {
	firstLabelEnd, _ := dns.NextLabel(owner, 0)
	if dnsname.CanonicalCompare(owner[:firstLabelEnd], "*.") != 0 {
		return 0, false
	}

	suffixLabels = dns.CountLabel(owner) - 1
	if qLabels <= suffixLabels {
		return 0, false
	}

	qnameSuffixStart := 0
	for labelsToSkip := qLabels - suffixLabels; labelsToSkip > 0; labelsToSkip-- {
		qnameSuffixStart, _ = dns.NextLabel(qname, qnameSuffixStart)
	}
	return suffixLabels, dnsname.CanonicalCompare(qname[qnameSuffixStart:], owner[firstLabelEnd:]) == 0
}

func writeReply(ch *middleware.Chain, req *dns.Msg, answers []dns.RR) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.RecursionAvailable = true
	msg.Answer = answers
	_ = ch.Writer.WriteMsg(msg)
	ch.Cancel()
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
