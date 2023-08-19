package loop

import (
	"context"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// Loop dummy type
type Loop struct{}

type ctxKey string

// New return loop
func New(cfg *config.Config) *Loop {
	return &Loop{}
}

// Name return middleware name
func (l *Loop) Name() string { return name }

// ServeDNS implements the Handle interface.
func (l *Loop) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req := ch.Request

	if len(req.Question) == 0 {
		ch.Cancel()
		return
	}

	qKey := req.Question[0].Name + ":" + dns.TypeToString[req.Question[0].Qtype]

	key := ctxKey("loopcheck:" + qKey)

	if v := ctx.Value(key); v != nil {
		count := v.(uint64)

		if count > 10 {
			log.Warn("Loop detected", "query", qKey)
			ch.CancelWithRcode(dns.RcodeServerFailure, false)
			return
		}

		count++
		ctx = context.WithValue(ctx, key, count)
	} else {
		ctx = context.WithValue(ctx, key, uint64(1))
	}

	ch.Next(ctx)
}

const name = "loop"
