package rpz

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"

	"github.com/miekg/dns"
)

// Skip reasons, the label values of rpz_zone_rules_skipped. A skipped
// record is stepped over and counted, never a load failure: one bad rule
// must not take down a multi-million-rule feed, and a feed carrying
// trigger types a later phase evaluates must load today.
const (
	// SkipTrigger is a trigger encoding a phase this build does not
	// evaluate yet (rpz-ip, rpz-nsdname, rpz-nsip).
	SkipTrigger = "trigger-unsupported"
	// SkipOwnerEncoding is a trigger owner the draft's encoding cannot
	// decode: a bad prefix length, a malformed reversed address, a
	// second zz.
	SkipOwnerEncoding = "owner-encoding"
	// SkipUnknownAction is a CNAME into the rpz-* action namespace that
	// no action this build knows — a future or nonstandard action code,
	// which must never be served as Local Data (design §5.2).
	SkipUnknownAction = "unknown-action"
	// SkipNotActionData covers the record types the draft excludes from
	// policy data: SOA and NS beyond the apex housekeeping, DNAME, and
	// the DNSSEC family a signed feed carries.
	SkipNotActionData = "not-action-data"
	// SkipConflict is a second action class at an owner that already has
	// one; the first rule stands.
	SkipConflict = "conflicting-rule"
	// SkipOutOfZone is a record whose owner is not under the origin.
	SkipOutOfZone = "out-of-zone"
	// SkipApexData is policy data at the zone apex itself, which names
	// no query and can trigger nothing.
	SkipApexData = "apex-data"
)

// pendingLimit bounds how many records may precede the apex SOA. Zone
// files and AXFR streams alike lead with the SOA; a file that has not
// produced one this deep in is not a policy zone.
const pendingLimit = 64

// IsDNSSECType reports whether t is one of the DNSSEC record types. The
// parser bars them from being policy data, and the middleware strips them
// from chased answers — one classification, shared, so the two cannot
// drift (a rewrite must never carry DNSSEC credibility, design C2).
func IsDNSSECType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM,
		dns.TypeDNSKEY, dns.TypeDS:
		return true
	}
	return false
}

// notActionData reports the types the draft bars from being policy data:
// zone housekeeping and the DNSSEC family.
func notActionData(t uint16) bool {
	switch t {
	case dns.TypeSOA, dns.TypeNS, dns.TypeDNAME:
		return true
	}
	return IsDNSSECType(t)
}

// triggerMarkers are the owner labels of trigger types later phases
// evaluate; everything under them is that trigger's encoding, not a name.
var triggerMarkers = []string{"rpz-nsdname", "rpz-nsip"}

// clientIPMarker selects the CLIENT-IP trigger, evaluated since phase 2.
const clientIPMarker = "rpz-client-ip"

// responseIPMarker selects the IP (response) trigger, evaluated since
// phase 4. The owner encoding is CLIENT-IP's exactly.
const responseIPMarker = "rpz-ip"

// LoadZoneFile parses one policy zone file into a compiled Zone. name is
// the config label; policy and cnameTarget come from the zone's config
// entry (cnameTarget canonical, used only with OverrideCNAME).
func LoadZoneFile(name, path string, policy Override, cnameTarget string) (*Zone, error) {
	f, err := os.Open(path) //nolint:gosec // G304 - the operator's configured policy file
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only descriptor

	return LoadZone(name, f, path, policy, cnameTarget)
}

// LoadZone is LoadZoneFile over a reader; file names the source in parse
// errors.
func LoadZone(name string, r io.Reader, file string, policy Override, cnameTarget string) (*Zone, error) {
	z := &Zone{
		Name:        name,
		Policy:      policy,
		CNAMETarget: cnameTarget,
		exact:       make(map[string]*Rule),
		wild:        make(map[string]*Rule),
		Skipped:     make(map[string]int),
	}

	// The origin is the apex SOA's owner. Records ahead of the SOA are
	// held back and classified once it arrives; a file that never gets
	// there is refused as not a zone.
	var pending []dns.RR

	zp := dns.NewZoneParser(r, "", file)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if z.Origin == "" {
			if soa, isSOA := rr.(*dns.SOA); isSOA {
				z.Origin = dns.CanonicalName(soa.Hdr.Name)
				z.SOA = soa
				for _, held := range pending {
					z.classify(held)
				}
				pending = nil
				continue
			}
			if len(pending) >= pendingLimit {
				return nil, fmt.Errorf("rpz zone %q: no SOA among the first %d records of %s", name, pendingLimit, file)
			}
			pending = append(pending, rr)
			continue
		}
		z.classify(rr)
	}
	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("rpz zone %q: %w", name, err)
	}
	if z.Origin == "" {
		return nil, fmt.Errorf("rpz zone %q: %s carries no SOA, so it has no origin", name, file)
	}
	return z, nil
}

// CompileRecords compiles an already-received record stream — an AXFR —
// into a Zone, through exactly the classifier the file loader uses, so a
// feed behaves identically whichever way it arrived. The stream must lead
// with its apex SOA, which a strict transfer guarantees; the caller
// normalizes duplicates first (zonetransfer.NormalizeZone), because the
// Local Data merge accumulates records and a doubled record must not read
// as two.
func CompileRecords(name string, rrs []dns.RR, policy Override, cnameTarget string) (*Zone, error) {
	if len(rrs) == 0 {
		return nil, fmt.Errorf("rpz zone %q: empty transfer", name)
	}
	soa, ok := rrs[0].(*dns.SOA)
	if !ok {
		return nil, fmt.Errorf("rpz zone %q: transfer does not lead with its SOA", name)
	}
	z := &Zone{
		Name:        name,
		Origin:      dns.CanonicalName(soa.Hdr.Name),
		SOA:         soa,
		Policy:      policy,
		CNAMETarget: cnameTarget,
		exact:       make(map[string]*Rule),
		wild:        make(map[string]*Rule),
		Skipped:     make(map[string]int),
	}
	for _, rr := range rrs[1:] {
		z.classify(rr)
	}
	return z, nil
}

// classify turns one record into a rule, or a counted skip.
func (z *Zone) classify(rr dns.RR) {
	hdr := rr.Header()
	owner := dns.CanonicalName(hdr.Name)

	// Relativize against the origin.
	var rel string
	switch {
	case owner == z.Origin:
		rel = ""
	case z.Origin == ".":
		rel = strings.TrimSuffix(owner, ".")
	case strings.HasSuffix(owner, "."+z.Origin):
		rel = owner[:len(owner)-len(z.Origin)-1]
	default:
		z.skip(SkipOutOfZone)
		return
	}

	// Apex records: the SOA was captured by the load loop; NS is the
	// zone's own housekeeping; anything else at the apex names no query.
	if rel == "" {
		switch hdr.Rrtype {
		case dns.TypeSOA, dns.TypeNS:
			z.skip(SkipNotActionData)
		default:
			z.skip(SkipApexData)
		}
		return
	}

	// Triggers of later phases wait for them.
	for _, marker := range triggerMarkers {
		if rel == marker || strings.HasSuffix(rel, "."+marker) {
			z.skip(SkipTrigger)
			return
		}
	}

	if notActionData(hdr.Rrtype) {
		z.skip(SkipNotActionData)
		return
	}

	// CLIENT-IP and IP: the owner encodes an address block, not a name.
	// The two triggers share one encoding and one merge semantic; only
	// the tables differ — one pair judges the querier, the other the
	// answer.
	if enc, ok := strings.CutSuffix(rel, "."+clientIPMarker); ok {
		z.insertIPOwner(enc, rr, z.insertClientIP)
		return
	}
	if enc, ok := strings.CutSuffix(rel, "."+responseIPMarker); ok {
		z.insertIPOwner(enc, rr, z.insertResponseIP)
		return
	}
	if rel == clientIPMarker || rel == responseIPMarker {
		// The bare marker owns no address.
		z.skip(SkipOwnerEncoding)
		return
	}

	action, local := classifyAction(rr)
	if action == ActionNone {
		z.skip(SkipUnknownAction)
		return
	}

	z.insert(rel, action, local)
}

// insertIPOwner decodes an address-encoded owner and hands the rule to
// the trigger's own filing function.
func (z *Zone) insertIPOwner(enc string, rr dns.RR, file func(netip.Prefix, Action, dns.RR)) {
	prefix, valid := parseClientIPOwner(enc)
	if !valid {
		z.skip(SkipOwnerEncoding)
		return
	}
	action, local := classifyAction(rr)
	if action == ActionNone {
		z.skip(SkipUnknownAction)
		return
	}
	file(prefix, action, local)
}

// insertClientIP and insertResponseIP file an address rule into their
// trigger's family tables.
func (z *Zone) insertClientIP(prefix netip.Prefix, action Action, local dns.RR) {
	z.insertIP(prefix, action, local, &z.clientIP4, &z.clientIP6, &z.RulesClientIP)
}

func (z *Zone) insertResponseIP(prefix netip.Prefix, action Action, local dns.RR) {
	z.insertIP(prefix, action, local, &z.responseIP4, &z.responseIP6, &z.RulesResponseIP)
}

// insertIP files an address rule with the same merge semantics as the
// name triggers: the first action class at a prefix stands, Local Data
// accumulates, anything else is a conflict. The prefix's family picks
// the table.
func (z *Zone) insertIP(prefix netip.Prefix, action Action, local dns.RR, t4, t6 **ipLPM, counter *int) {
	table := t6
	if prefix.Addr().Is4() {
		table = t4
	}
	if *table == nil {
		*table = &ipLPM{}
	}
	if existing := (*table).lookupExact(prefix); existing != nil {
		if existing.Action == ActionLocalData && action == ActionLocalData {
			existing.Local = append(existing.Local, local)
			return
		}
		z.skip(SkipConflict)
		return
	}
	rule := &Rule{Action: action}
	if action == ActionLocalData {
		rule.Local = []dns.RR{local}
	}
	(*table).insert(prefix, rule)
	z.Rules++
	*counter++
}

// insert files a rule under its relative owner. The first action class at
// an owner stands; Local Data accumulates records, anything else arriving
// at an occupied owner is a conflict.
func (z *Zone) insert(rel string, action Action, local dns.RR) {
	var (
		slot     map[string]*Rule
		key      string
		existing *Rule
	)
	switch {
	case rel == "*":
		existing = z.matchAll
	case strings.HasPrefix(rel, "*."):
		slot, key = z.wild, rel[2:]+"."
		existing = slot[key]
	default:
		slot, key = z.exact, rel+"."
		existing = slot[key]
	}

	if existing != nil {
		if existing.Action == ActionLocalData && action == ActionLocalData {
			existing.Local = append(existing.Local, local)
			return
		}
		z.skip(SkipConflict)
		return
	}

	rule := &Rule{Action: action}
	if action == ActionLocalData {
		rule.Local = []dns.RR{local}
	}
	if rel == "*" {
		z.matchAll = rule
	} else {
		slot[key] = rule
	}
	z.Rules++
}

func (z *Zone) skip(reason string) { z.Skipped[reason]++ }

// classifyAction reads the action off one record's RDATA per the draft's
// encoding. ActionNone means "refuse as unknown-action"; for
// ActionLocalData the record itself is the payload.
func classifyAction(rr dns.RR) (Action, dns.RR) {
	cname, ok := rr.(*dns.CNAME)
	if !ok {
		return ActionLocalData, rr
	}
	switch target := dns.CanonicalName(cname.Target); target {
	case ".":
		return ActionNXDOMAIN, nil
	case "*.":
		return ActionNODATA, nil
	case "rpz-passthru.":
		return ActionPassthru, nil
	case "rpz-drop.":
		return ActionDrop, nil
	case "rpz-tcp-only.":
		return ActionTCPOnly, nil
	default:
		// A target whose top-level label sits in the rpz-* namespace is
		// an action code, recognized or not — never Local Data. The
		// wildcard form steps over "*." so a wildcarded rpz-* target is
		// judged by the same rule.
		tld := strings.TrimPrefix(target, "*.")
		tld = strings.TrimSuffix(tld, ".")
		if i := strings.LastIndexByte(tld, '.'); i >= 0 {
			tld = tld[i+1:]
		}
		if strings.HasPrefix(tld, "rpz-") {
			return ActionNone, nil
		}
		return ActionLocalData, rr
	}
}
