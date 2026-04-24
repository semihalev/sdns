package middleware

import "github.com/miekg/dns"

// Purger is implemented by handlers that maintain cacheable state
// which can be invalidated by question. The cache middleware and the
// resolver handler both implement it — Cache purges its positive /
// negative entries, the resolver purges its nameserver cache.
//
// The api purge endpoint iterates every Purger in the pipeline
// instead of synthesising a CHAOS-NULL query and routing it through
// ServeDNS; that keeps purge as a side-effect operation rather than
// a pseudo-DNS flow that has to survive every middleware on the way
// through.
type Purger interface {
	Purge(q dns.Question)
}
