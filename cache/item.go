package cache

import (
	"time"

	"github.com/miekg/dns"
)

type item struct {
	Rcode              int
	Authoritative      bool
	AuthenticatedData  bool
	RecursionAvailable bool
	Answer             []dns.RR
	Ns                 []dns.RR
	Extra              []dns.RR

	origTTL uint32
	stored  time.Time
}

func newItem(m *dns.Msg, now time.Time, d time.Duration) *item {
	i := new(item)
	i.Rcode = m.Rcode
	i.Authoritative = m.Authoritative
	i.AuthenticatedData = m.AuthenticatedData
	i.RecursionAvailable = m.RecursionAvailable

	i.Answer = make([]dns.RR, len(m.Answer))
	i.Ns = make([]dns.RR, len(m.Ns))
	i.Extra = make([]dns.RR, len(m.Extra))

	for j, r := range m.Answer {
		i.Answer[j] = dns.Copy(r)
	}
	for j, r := range m.Ns {
		i.Ns[j] = dns.Copy(r)
	}
	for j, r := range m.Extra {
		i.Extra[j] = dns.Copy(r)
	}

	i.origTTL = uint32(d.Seconds())
	i.stored = now.UTC()

	return i
}

func (i *item) toMsg(m *dns.Msg) *dns.Msg {
	m1 := new(dns.Msg)
	m1.SetReply(m)

	m1.Authoritative = false
	m1.AuthenticatedData = i.AuthenticatedData
	m1.RecursionAvailable = i.RecursionAvailable
	m1.Rcode = i.Rcode

	m1.Answer = make([]dns.RR, len(i.Answer))
	m1.Ns = make([]dns.RR, len(i.Ns))
	m1.Extra = make([]dns.RR, len(i.Extra))

	for j, r := range i.Answer {
		m1.Answer[j] = dns.Copy(r)
	}
	for j, r := range i.Ns {
		m1.Ns[j] = dns.Copy(r)
	}
	for j, r := range i.Extra {
		m1.Extra[j] = dns.Copy(r)
	}
	return m1
}

func (i *item) ttl(now time.Time) int {
	ttl := int(i.origTTL) - int(now.UTC().Sub(i.stored).Seconds())
	return ttl
}
