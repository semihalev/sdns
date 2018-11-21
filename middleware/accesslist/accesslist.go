package accesslist

import (
	"net"

	"github.com/semihalev/sdns/middleware"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/ctx"
	"github.com/yl2chen/cidranger"
)

// AccessList type
type AccessList struct {
	ranger cidranger.Ranger
}

func init() {
	middleware.Register(name, func(cfg *config.Config) ctx.Handler {
		return New(cfg)
	})
}

// New return accesslist
func New(cfg *config.Config) *AccessList {
	a := new(AccessList)
	a.ranger = cidranger.NewPCTrieRanger()
	for _, cidr := range cfg.AccessList {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Error("Access list parse cidr failed", "error", err.Error())
			continue
		}

		a.ranger.Insert(cidranger.NewBasicRangerEntry(*ipnet))
	}

	return a
}

// Name return middleware name
func (a *AccessList) Name() string { return name }

// ServeDNS implements the Handle interface.
func (a *AccessList) ServeDNS(dc *ctx.Context) {
	client, _, _ := net.SplitHostPort(dc.DNSWriter.RemoteAddr().String())
	allowed, _ := a.ranger.Contains(net.ParseIP(client))

	if !allowed {
		//no reply to client
		dc.Abort()
		return
	}

	dc.NextDNS()
}

const name = "accesslist"
