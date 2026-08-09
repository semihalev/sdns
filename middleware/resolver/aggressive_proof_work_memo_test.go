package resolver

import (
	"context"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/resolver/dnssec"
)

func resolverMemoNODATAFixture() (*dns.Msg, []dns.RR, string) {
	const (
		qname = "memo.example."
		zone  = "example."
	)
	hash := dns.HashName(qname, dns.SHA1, 0, "")
	msg := new(dns.Msg).SetQuestion(qname, dns.TypeA)
	records := []dns.RR{&dns.NSEC3{
		Hdr: dns.RR_Header{
			Name:   hash + "." + zone,
			Rrtype: dns.TypeNSEC3,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Hash:       dns.SHA1,
		HashLength: 20,
		NextDomain: hash,
	}}
	return msg, records, zone
}

func resolverMemoWorkContext(t *testing.T) (context.Context, *middleware.RecursionWorkLedger) {
	t.Helper()
	ctx, ledger := middleware.EnsureRecursionWork(
		context.Background(),
		middleware.RecursionWorkPolicy{
			Mode:           middleware.RecursionWorkEnforce,
			MaxNSEC3Hashes: 4,
		},
	)
	if ledger == nil {
		t.Fatal("enforce policy did not create a recursion-work ledger")
	}
	return dnssec.EnsureNSEC3HashMemo(ctx), ledger
}

func TestResolverNSEC3HashMemoRequiredAndOptionalDirection(t *testing.T) {
	t.Run("required result is readable by optional work", func(t *testing.T) {
		ctx, ledger := resolverMemoWorkContext(t)
		msg, records, zone := resolverMemoNODATAFixture()

		required := dnssecWorkBudget{ctx: ctx}
		secure, err := dnssec.VerifyNODATAForZoneWithWork(msg, records, zone, required)
		if err != nil || !secure {
			t.Fatalf("required NODATA verification = secure:%t err:%v", secure, err)
		}
		if got := ledger.Snapshot().NSEC3Hashes; got != 1 {
			t.Fatalf("required NSEC3 hash debits = %d, want 1", got)
		}

		optional := newResolverAggressiveProofWork(ctx, nil)
		secure, err = dnssec.VerifyNODATAForZoneWithWork(msg, records, zone, optional)
		if err != nil || !secure {
			t.Fatalf("optional NODATA verification = secure:%t err:%v", secure, err)
		}
		if got := optional.memo.WorkUsed(); got != 0 {
			t.Fatalf("optional reread hash debits = %d, want 0", got)
		}
		if got := ledger.Snapshot().NSEC3Hashes; got != 1 {
			t.Fatalf("optional reread changed required ledger to %d, want 1", got)
		}
	})

	t.Run("optional result stays private from required work", func(t *testing.T) {
		ctx, ledger := resolverMemoWorkContext(t)
		msg, records, zone := resolverMemoNODATAFixture()

		optional := newResolverAggressiveProofWork(ctx, nil)
		secure, err := dnssec.VerifyNODATAForZoneWithWork(msg, records, zone, optional)
		if err != nil || !secure {
			t.Fatalf("optional NODATA verification = secure:%t err:%v", secure, err)
		}
		if got := optional.memo.WorkUsed(); got != 1 {
			t.Fatalf("optional NSEC3 hash debits = %d, want 1", got)
		}
		if got := ledger.Snapshot().NSEC3Hashes; got != 0 {
			t.Fatalf("optional work changed required ledger to %d, want 0", got)
		}

		required := dnssecWorkBudget{ctx: ctx}
		secure, err = dnssec.VerifyNODATAForZoneWithWork(msg, records, zone, required)
		if err != nil || !secure {
			t.Fatalf("required NODATA verification after optional = secure:%t err:%v", secure, err)
		}
		if got := ledger.Snapshot().NSEC3Hashes; got != 1 {
			t.Fatalf("required NSEC3 hash debits after optional result = %d, want 1", got)
		}
	})
}

func TestResolverNSEC3HashMemoAdapterOwnership(t *testing.T) {
	ctx := dnssec.EnsureNSEC3HashMemo(context.Background())
	shared := dnssec.NSEC3HashMemoFromContext(ctx)
	if shared == nil {
		t.Fatal("request context has no NSEC3 memo")
	}

	required := (dnssecWorkBudget{ctx: ctx}).NSEC3HashMemos()
	if required.Read != shared || required.Write != shared {
		t.Fatal("required adapter does not read and write the request-tree memo")
	}

	firstOptional := newResolverAggressiveProofWork(ctx, nil)
	optional := firstOptional.NSEC3HashMemos()
	if optional.Read != shared {
		t.Fatal("resolver optional adapter cannot read the request-tree memo")
	}
	if optional.Write == nil || optional.Write == shared {
		t.Fatal("resolver optional adapter does not write to its private memo")
	}
	secondOptional := newResolverAggressiveProofWork(ctx, nil)
	if secondOptional.memo != firstOptional.memo {
		t.Fatal("resolver optional adapters reset the request-tree private memo")
	}
}

func TestResolverAggressiveProofHashLimitSpansAdapters(t *testing.T) {
	ctx := dnssec.EnsureNSEC3HashMemo(context.Background())
	first := newResolverAggressiveProofWork(ctx, nil)
	second := newResolverAggressiveProofWork(ctx, nil)

	for i := uint32(0); i < resolverAggressiveProofMaxNSEC3Hashes; i++ {
		work := first
		if i >= resolverAggressiveProofMaxNSEC3Hashes/2 {
			work = second
		}
		release, err := work.BeginNSEC3Hash()
		if err != nil {
			t.Fatalf("optional hash %d: %v", i+1, err)
		}
		release()
	}
	if _, err := second.BeginNSEC3Hash(); err != errResolverAggressiveProofHashLimit {
		t.Fatalf("cross-adapter limit error = %v, want %v",
			err, errResolverAggressiveProofHashLimit)
	}
}
