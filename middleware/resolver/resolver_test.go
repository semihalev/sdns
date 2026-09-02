package resolver

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Resolution itself, an ordinary answer, QNAME minimisation, NXDOMAIN,
// NODATA, an authority that never replies, the root's own keys, and every
// DNSSEC verdict from a valid chain to a DS that matches no key, is
// covered against a signed loopback namespace in hermetic_resolver_test.go
// and hermetic_dnssec_test.go. Those cases used to be borrowed from
// third-party zones, which made them fail whenever a zone changed its
// configuration or the network misbehaved; one had already been skipped for
// that reason, and root-server detection had been removed from the resolver
// entirely while its test lived on as a skip.

func Test_EqualServers(t *testing.T) {
	r := newWiredTestResolver(makeTestConfig())
	if !reflect.DeepEqual(true, r.equalServers(r.rootServers, r.rootServers)) {
		t.Errorf("r.equalServers(r.rootServers, r.rootServers) = %v, want %v", r.equalServers(r.rootServers, r.rootServers), true)
	}
}

func Test_OutboundIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	cfg := makeTestConfig()
	cfg.OutboundIPs = []string{"127.0.0.1", "1"}
	cfg.OutboundIP6s = []string{"::1", "1"}

	r := newWiredTestResolver(cfg)
	if len(r.outboundIPv4) != 1 {
		t.Errorf("len(r.outboundIPv4) = %d, want %d", len(r.outboundIPv4), 1)
	}
	if len(r.outboundIPv6) != 1 {
		t.Errorf("len(r.outboundIPv6) = %d, want %d", len(r.outboundIPv6), 1)
	}

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.CheckingDisabled = true

	// Use a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.lookup(ctx, &resolveState{requestID: req.Id}, req, r.rootServers)
	if err == nil {
		t.Errorf("expected an error, got nil")
	}
}
