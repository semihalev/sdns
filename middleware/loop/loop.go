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

func init() {
	middleware.Register(name, func(cfg *config.Config) middleware.Handler {
		return New(cfg)
	})
}

// New return loop
func New(cfg *config.Config) *Loop {
	return &Loop{}
}

// Name return middleware name
func (l *Loop) Name() string { return name }

// ServeDNS implements the Handle interface.
func (l *Loop) ServeDNS(ctx context.Context, ch *middleware.Chain) {
	req := ch.Request
	qKey := req.Question[0].Name + ":" + dns.TypeToString[req.Question[0].Qtype]

	key := ctxKey("loopcheck:" + qKey)

	if v := ctx.Value(key); v != nil {
		list := v.([]string)

		loopCount := 0
		for _, n := range list {
			if n == qKey {
				loopCount++
				if loopCount > 10 {
					log.Warn("Loop detected", "query", qKey)
					ch.CancelWithRcode(dns.RcodeServerFailure, false)
				}
			}
		}

		list = append(list, qKey)
		ctx = context.WithValue(ctx, key, list)
	} else {
		ctx = context.WithValue(ctx, key, []string{qKey})
	}

	ch.Next(ctx)
}

const name = "loop"
