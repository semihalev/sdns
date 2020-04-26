package loop

import (
	"strings"
	"sync"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/cache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
)

// Loop type
type Loop struct {
	sync.Mutex

	count map[uint64]int
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New returns a new Loop
func New(cfg *config.Config) *Loop {
	return &Loop{
		count: make(map[uint64]int),
	}
}

// Name return middleware name
func (l *Loop) Name() string { return name }

// ServeDNS implements the Handle interface.
func (l *Loop) ServeDNS(dc *ctx.Context) {
	w, req := dc.DNSWriter, dc.DNSRequest

	if w.Internal() {
		q := req.Question[0]

		key := cache.Hash(q, req.CheckingDisabled)

		if l.Count(key) > loopCount {
			log.Warn("Iteration looping, request aborted", "query", formatQuestion(q))

			w.WriteMsg(dnsutil.HandleFailed(req, dns.RcodeServerFailure, false))

			dc.Abort()
			return
		}
	}

	dc.NextDNS()
}

// Count loop times
func (l *Loop) Count(key uint64) int {
	l.Lock()
	defer l.Unlock()

	if c, ok := l.count[key]; ok {
		c++
		l.count[key] = c

		return c
	}

	l.count[key] = 1

	return 1
}

func formatQuestion(q dns.Question) string {
	return strings.ToLower(q.Name) + " " + dns.ClassToString[q.Qclass] + " " + dns.TypeToString[q.Qtype]
}

const (
	name      = "loop"
	loopCount = 100
)
