package resolver

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/util"
	"github.com/stretchr/testify/assert"
)

func Test_resolver(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)

	servers, _, _ := r.searchCache(req.Question[0], req.CheckingDisabled, "google.com.")
	assert.Equal(t, true, len(servers.List) > 0)
	atomic.AddUint32(&servers.ErrorCount, 4)

	servers.List = []*authcache.AuthServer{authcache.NewAuthServer("0.0.0.0:0", authcache.IPv4)}

	resp, err = r.Resolve(ctx, req, servers, false, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverMinimize(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("www.apple.com.", dns.TypeA)
	req.CheckingDisabled = true

	cfg := makeTestConfig()
	cfg.QnameMinLevel = 5

	r := NewResolver(cfg)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverDNSSEC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("good.dnssec-or-not.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverBadDNSSEC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("dnssec-failed.org.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNoSigDNSSEC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// This name is intentionally constructed under a signed zone but returns
	// responses missing signatures ("nosig"), used by dnscheck.tools.
	qname := "nosig-e5ecc382.test-alg15.dnscheck.tools."

	req := new(dns.Msg)
	req.SetQuestion(qname, dns.TypeA)
	// Ask for DNSSEC records (DO=1) so we can observe how the resolver handles
	// missing/bogus signatures under a signed zone.
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)
	if err != nil {
		t.Logf("nosig resolve error: %v", err)
	}
	if resp != nil {
		t.Logf("nosig resolve rcode=%s ad=%v answers=%d ns=%d extra=%d", dns.RcodeToString[resp.Rcode], resp.AuthenticatedData, len(resp.Answer), len(resp.Ns), len(resp.Extra))
	}

	// Expected behavior: signed zone missing required signatures should be treated
	// as bogus and fail closed.
	assert.Error(t, err)
	assert.True(t, errors.Is(err, errNoSignatures), "expected errNoSignatures, got %v", err)
	assert.Nil(t, resp)
}

func Test_resolverBadKeyDNSSEC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("bad.dnssec-or-not.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverExponentDNSSEC(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("verteiltesysteme.net.", dns.TypeNS)
	req.SetEdns0(4096, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverDS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("nic.cz.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	resp, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
	assert.Equal(t, len(resp.Answer) > 0, true)
}

func Test_resolverAllNS(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("sds4wdwf.", dns.TypeNS)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverTimeout(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("baddns.com.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverRootServersDetect(t *testing.T) {
	t.Skip("Skipping test for root server detection, no detect anymore.")
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("12.137.53.1.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNameserverError(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("33.38.244.195.in-addr.arpa.", dns.TypePTR)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.Error(t, err)
}

func Test_resolverNSEC3nodata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("asdadadasds33sa.co.uk.", dns.TypeDS)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNSECnodata(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("tr.", dns.TypeDS)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNSEC3nodataerror(t *testing.T) {
	t.Parallel()
	t.Skip("Skipping: testlabs.example.com DNSSEC configuration is currently broken (external dependency)")

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("testlabs.example.com.", dns.TypeDS)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverFindSigner(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("c-73-136-41-228.hsd1.tx.comcast.net.", dns.TypeA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverRootKeys(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeDNSKEY)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_resolverNoAnswer(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	req := new(dns.Msg)
	req.SetQuestion("www.sozcu.com.tr.", dns.TypeAAAA)
	req.SetEdns0(util.DefaultMsgSize, true)

	cfg := makeTestConfig()
	r := NewResolver(cfg)

	_, err := r.Resolve(ctx, req, r.rootservers, true, 30, 0, false, nil)

	assert.NoError(t, err)
}

func Test_EqualServers(t *testing.T) {
	r := NewResolver(makeTestConfig())
	assert.Equal(t, true, r.equalServers(r.rootservers, r.rootservers))
}

func Test_OutboundIPs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	cfg := makeTestConfig()
	cfg.OutboundIPs = []string{"127.0.0.1", "1"}
	cfg.OutboundIP6s = []string{"::1", "1"}

	r := NewResolver(cfg)
	assert.Len(t, r.outboundipv4, 1)
	assert.Len(t, r.outboundipv6, 1)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.CheckingDisabled = true

	// Use a timeout context to prevent hanging
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := r.lookup(ctx, req, r.rootservers)
	assert.Error(t, err)
}
