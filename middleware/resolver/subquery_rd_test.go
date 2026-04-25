package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
)

// TestSubQueryClearsRDAD pins the Phase-6-P2 behaviour: DS/DNSKEY
// requests constructed via dns.Msg.SetQuestion carry RD=true by
// default; subQuery must clear both RD and AD before the request
// reaches an authoritative server, the same way DNSHandler.handle
// does at handler.go:134-135 for chain-dispatched queries. Missing
// this clear had the resolver ask authorities for recursion,
// tripping REFUSED on stricter implementations.
//
// A Resolver{} with no root servers fails closed in subQuery before
// r.resolve runs, which is exactly after the RD/AD clear lands —
// letting us assert the mutation happened without a real upstream.
func TestSubQueryClearsRDAD(t *testing.T) {
	r := &Resolver{}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeDS)
	req.RecursionDesired = true
	req.AuthenticatedData = true

	if _, err := r.subQuery(context.Background(), req); err == nil {
		t.Fatal("expected errNoRootServers from Resolver{}; got nil")
	}

	if req.RecursionDesired {
		t.Error("subQuery must clear RecursionDesired before authoritative dispatch")
	}
	if req.AuthenticatedData {
		t.Error("subQuery must clear AuthenticatedData before authoritative dispatch")
	}
}
