package resolver

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/authority"
	"github.com/semihalev/sdns/internal/cache"
	"github.com/semihalev/sdns/internal/lease"
	"github.com/semihalev/sdns/middleware"
)

// setReferralTTL makes the root hand out z's delegation, its NS set and
// glue, with ttl, so a test can watch a lease end in seconds.
func setReferralTTL(n *hermeticNet, z *hermeticZone, ttl uint32) {
	n.root.mu.Lock()
	defer n.root.mu.Unlock()
	ref := n.root.children[z.name]
	for _, rr := range ref.ns {
		if rr.Header().Rrtype == dns.TypeNS {
			rr.Header().Ttl = ttl
		}
	}
	for _, rr := range ref.extra {
		rr.Header().Ttl = ttl
	}
}

// withRefreshShare widens the refresh window for a test: share 2 is the
// last half of a lease.
func withRefreshShare(t *testing.T, share int64) {
	old := delegationRefreshShare.Swap(share)
	t.Cleanup(func() { delegationRefreshShare.Store(old) })
}

func resolveA(t *testing.T, h *DNSHandler, name string) *dns.Msg {
	t.Helper()
	req := new(dns.Msg)
	req.SetQuestion(name, dns.TypeA)
	req.SetEdns0(1232, true)
	ctx := middleware.WithResponseMeta(context.Background(), new(middleware.ResponseMeta))
	resp := h.handle(ctx, req)
	if resp == nil || resp.Rcode != dns.RcodeSuccess || len(resp.Answer) == 0 {
		t.Fatalf("%s: %v, want an answer", name, resp)
	}
	return resp
}

// TestDelegationRefreshedBeforeItsLeaseEnds: a delegation used near the end
// of its lease is renewed from the parent, so resolution under it goes on
// past the old end without asking the parent again, and the renewed lease
// is the fresh referral's, never more.
func TestDelegationRefreshedBeforeItsLeaseEnds(t *testing.T) {
	withRefreshShare(t, 2)
	const ttl = 2 // seconds, the referral's NS and glue TTL

	net := newHermeticNet(t)
	zone := net.DelegateInsecure("refresh.test.")
	setReferralTTL(net, zone, ttl)
	for _, name := range []string{"a", "b", "c"} {
		zone.Serve(mustRR(t, name+".refresh.test. 300 IN A 192.0.2.80"))
	}
	h := net.Handler()
	r := h.resolver
	key := cache.Key(dns.Question{Name: "refresh.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)

	resolveA(t, h, "a.refresh.test.")
	first, err := r.delegations.Get(key)
	if err != nil {
		t.Fatalf("delegation not cached: %v", err)
	}
	oldEnd := first.Lease.Mono().Until
	referrals := net.root.asked("refresh.test.", dns.TypeA) + net.root.asked("refresh.test.", dns.TypeNS)
	renewedBefore := delegationRefreshes.renewed.Value()

	// Into the last half of the lease: this use schedules the refresh.
	time.Sleep(time.Until(oldEnd.Add(-700 * time.Millisecond)))
	refreshAt := time.Now()
	resolveA(t, h, "b.refresh.test.")

	var renewed time.Time
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if d, err := r.delegations.Get(key); err == nil && d != first {
			renewed = d.Lease.Mono().Until
			break
		}
	}
	if renewed.IsZero() {
		t.Fatal("delegation was not renewed before its lease ended")
	}
	if !renewed.After(oldEnd) {
		t.Fatalf("renewed lease ends %v, not after the old end %v", renewed, oldEnd)
	}
	if limit := time.Now().Add(ttl * time.Second); renewed.After(limit) || renewed.Before(refreshAt) {
		t.Fatalf("renewed lease ends %v, want within the fresh referral's %ds", renewed, ttl)
	}

	// Past the old end: the renewed delegation serves, the root is not
	// asked for it again.
	time.Sleep(time.Until(oldEnd.Add(200 * time.Millisecond)))
	afterRefresh := net.root.asked("refresh.test.", dns.TypeA) + net.root.asked("refresh.test.", dns.TypeNS)
	resolveA(t, h, "c.refresh.test.")
	if got := net.root.asked("refresh.test.", dns.TypeA) + net.root.asked("refresh.test.", dns.TypeNS); got != afterRefresh {
		t.Fatalf("root asked again past the old lease end (%d, was %d): the renewed delegation was not used", got, afterRefresh)
	}
	if afterRefresh <= referrals {
		t.Fatalf("the refresh never asked the root (%d, was %d)", afterRefresh, referrals)
	}
	if delegationRefreshes.renewed.Value() <= renewedBefore {
		t.Fatal("the renewal was not counted")
	}
}

// TestDelegationRefreshFailureKeepsTheOldLease: a refresh that cannot reach
// the parent changes nothing; the delegation serves to its old end and is
// gone after it, as without a refresh.
func TestDelegationRefreshFailureKeepsTheOldLease(t *testing.T) {
	withRefreshShare(t, 2)
	net := newHermeticNet(t)
	zone := net.DelegateInsecure("refresh.test.")
	setReferralTTL(net, zone, 2)
	for _, name := range []string{"a", "b"} {
		zone.Serve(mustRR(t, name+".refresh.test. 300 IN A 192.0.2.80"))
	}
	h := net.Handler()
	r := h.resolver
	key := cache.Key(dns.Question{Name: "refresh.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)

	resolveA(t, h, "a.refresh.test.")
	first, err := r.delegations.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	oldEnd := first.Lease.Mono().Until

	net.root.silence()
	asked := net.root.asked("refresh.test.", dns.TypeNS)
	failedBefore := delegationRefreshes.failed.Value()
	time.Sleep(time.Until(oldEnd.Add(-700 * time.Millisecond)))
	resolveA(t, h, "b.refresh.test.")

	// The refresh runs against the silent root while the old lease runs
	// out; the entry is the very one stored to its end and gone after it.
	time.Sleep(time.Until(oldEnd.Add(-100 * time.Millisecond)))
	if d, err := r.delegations.Get(key); err != nil || d != first {
		t.Fatalf("the delegation did not serve to its old end unchanged (err %v)", err)
	}
	time.Sleep(time.Until(oldEnd.Add(100 * time.Millisecond)))
	if _, err := r.delegations.Get(key); err == nil {
		t.Fatal("the delegation outlived its lease after a failed refresh")
	}

	// The refresh fails, is counted as such, and gives its claim back.
	for deadline := time.Now().Add(15 * time.Second); delegationRefreshes.failed.Value() <= failedBefore; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the failed refresh was not counted")
		}
	}
	if net.root.asked("refresh.test.", dns.TypeNS) == asked {
		t.Fatal("no refresh asked the root")
	}
	if !first.ClaimRefresh() {
		t.Fatal("the failed refresh kept its claim")
	}
}

// TestDelegationRefreshInheritsTheParentCut: a renewed delegation is bound
// by its parent's lease as any referral is, however long the fresh referral
// grants: the refresh renews, it never outlives an ancestor.
func TestDelegationRefreshInheritsTheParentCut(t *testing.T) {
	withRefreshShare(t, 2)
	net := newHermeticNet(t)
	zone := net.DelegateInsecure("refresh.test.")
	setReferralTTL(net, zone, 2)
	for _, name := range []string{"a", "b"} {
		zone.Serve(mustRR(t, name+".refresh.test. 300 IN A 192.0.2.80"))
	}
	h := net.Handler()
	r := h.resolver
	key := cache.Key(dns.Question{Name: "refresh.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)

	resolveA(t, h, "a.refresh.test.")
	first, err := r.delegations.Get(key)
	if err != nil {
		t.Fatal(err)
	}
	oldEnd := first.Lease.Mono().Until

	// The fresh referral would grant a minute; the parent above it, a
	// "test." delegation served by the same root, has far less left.
	setReferralTTL(net, zone, 60)
	time.Sleep(time.Until(oldEnd.Add(-700 * time.Millisecond)))
	parentEnd := time.Now().Add(1500 * time.Millisecond)
	parentKey := cache.Key(dns.Question{Name: "test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)
	r.delegations.SetUntil(parentKey, nil, &authority.Servers{
		Zone: "test.",
		List: []*authority.Server{authority.NewServer(net.root.addr, authority.IPv4)},
	}, lease.Until(parentEnd))
	resolveA(t, h, "b.refresh.test.")

	var renewed time.Time
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if d, err := r.delegations.Get(key); err == nil && d != first {
			renewed = d.Lease.Mono().Until
			break
		}
	}
	if renewed.IsZero() {
		t.Fatal("delegation was not renewed")
	}
	if renewed.After(parentEnd) {
		t.Fatalf("renewed lease ends %v, after its parent's %v", renewed, parentEnd)
	}
}

// TestLocalRootDelegationRenewedFromTheCopy: under a local root copy, a due
// TLD delegation is renewed from the copy, the referral the walk would have
// asked a root server for, and the walk takes the renewed entry. A walk that
// is not a refresh leaves the live entry alone.
func TestLocalRootDelegationRenewedFromTheCopy(t *testing.T) {
	withRefreshShare(t, 1) // every live entry is due
	r, _ := localRootTestResolver(t)
	key := cache.Key(dns.Question{Name: "com.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)

	if _, handled := r.consultLocalRoot(context.Background(), localRootState("www.example.com.", dns.TypeA, false)); handled {
		t.Fatal("referral consult synthesized an answer")
	}
	first, err := r.delegations.Get(key)
	if err != nil {
		t.Fatalf("TLD delegation not installed: %v", err)
	}

	again := localRootState("www.example.com.", dns.TypeA, false)
	r.consultLocalRoot(context.Background(), again)
	if d, _ := r.delegations.Get(key); d != first || again.servers != first.Servers {
		t.Fatal("a walk that is not a refresh renewed the TLD delegation")
	}

	refresh := localRootState("example.com.", dns.TypeNS, false)
	refresh.refresh = true
	r.consultLocalRoot(context.Background(), refresh)
	renewed, err := r.delegations.Get(key)
	if err != nil || renewed == first {
		t.Fatalf("refresh did not renew the TLD delegation from the copy (err %v)", err)
	}
	if refresh.servers != renewed.Servers {
		t.Fatal("the refresh walk did not take the renewed entry")
	}
	snap := r.localRoot.Load().Active()
	if now := time.Now(); leaseLeft(renewed.Lease, now) > leaseLeft(snap.ValidUntil(), now) {
		t.Fatalf("renewed lease %+v outlives the copy's horizon %+v", renewed.Lease, snap.ValidUntil())
	}
}

// TestGlueRefreshedWhenReadNearItsEnd: a nameserver's address read from the
// glue cache near the end of its lifetime is resolved again in the
// background and stored afresh, so glue a delegation is built from is
// renewed while in use; read earlier, it is left alone.
func TestGlueRefreshedWhenReadNearItsEnd(t *testing.T) {
	world := newHermeticNet(t)
	helper := world.Delegate("helper.test.")
	shop := world.DelegateVia("shop.test.", "ns1.helper.test.")
	for _, name := range []string{"a", "b", "c"} {
		shop.Serve(mustRR(t, name+".shop.test. 300 IN A 192.0.2.60"))
	}
	helper.Serve(mustRR(t, "ns1.helper.test. 300 IN A "+shop.glue.String()))
	h := world.Handler()
	r := h.resolver
	shopKey := cache.Key(dns.Question{Name: "shop.test.", Qtype: dns.TypeNS, Qclass: dns.ClassINET}, false)
	glueKey := cache.Key(dns.Question{Name: "ns1.helper.test.", Qtype: dns.TypeA, Qclass: dns.ClassINET})

	resolveA(t, h, "a.shop.test.")
	first, ok := r.glueV4.Get(glueKey)
	if !ok {
		t.Fatal("the nameserver's address was not cached as glue")
	}
	asked := helper.asked("ns1.helper.test.", dns.TypeA)

	// Early in its life: rebuilding the delegation reads the glue and
	// leaves it alone.
	r.delegations.Remove(shopKey)
	resolveA(t, h, "b.shop.test.")
	time.Sleep(200 * time.Millisecond)
	if got, _ := r.glueV4.Get(glueKey); got != first || helper.asked("ns1.helper.test.", dns.TypeA) != asked {
		t.Fatal("glue read early in its life was refreshed")
	}

	// Near its end, every live entry being due: the read renews it.
	withRefreshShare(t, 1)
	r.delegations.Remove(shopKey)
	resolveA(t, h, "c.shop.test.")
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if got, ok := r.glueV4.Get(glueKey); ok && got != first {
			if helper.asked("ns1.helper.test.", dns.TypeA) == asked {
				t.Fatal("glue replaced without asking its zone again")
			}
			return
		}
	}
	t.Fatal("glue read near its end was not refreshed")
}
