package middleware

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/dnsutil"
	"github.com/semihalev/sdns/internal/mock"
)

func TestRecursionWorkLedgerShadowRecordsLimitCrossings(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 2,
		MaxInternalQueries: 1,
	})

	for range 4 {
		if err := ledger.Debit(RecursionWorkOutboundQuery); err != nil {
			t.Fatalf("shadow outbound debit returned error: %v", err)
		}
	}
	for range 3 {
		if err := ledger.Debit(RecursionWorkInternalQuery); err != nil {
			t.Fatalf("shadow internal debit returned error: %v", err)
		}
	}

	got := ledger.Snapshot()
	if got.Mode != RecursionWorkShadow {
		t.Fatalf("mode = %v, want shadow", got.Mode)
	}
	if got.OutboundQueries != 4 || got.InternalQueries != 3 {
		t.Fatalf("counts = outbound:%d internal:%d, want outbound:4 internal:3",
			got.OutboundQueries, got.InternalQueries)
	}
	if !got.OutboundExhausted || !got.InternalExhausted {
		t.Fatalf("exhausted = outbound:%v internal:%v, want both true",
			got.OutboundExhausted, got.InternalExhausted)
	}
	if got.MaxOutboundQueries != 2 || got.MaxInternalQueries != 1 {
		t.Fatalf("limits = outbound:%d internal:%d, want outbound:2 internal:1",
			got.MaxOutboundQueries, got.MaxInternalQueries)
	}
	if err := ledger.EnforcementError(); err != nil {
		t.Fatalf("shadow EnforcementError = %v, want nil", err)
	}
}

func TestRecursionWorkLedgerEnforceConcurrentExactCap(t *testing.T) {
	const (
		limit    = uint32(37)
		attempts = 256
	)

	tests := []struct {
		name string
		kind RecursionWorkKind
	}{
		{name: "outbound", kind: RecursionWorkOutboundQuery},
		{name: "internal", kind: RecursionWorkInternalQuery},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
				Mode:               RecursionWorkEnforce,
				MaxOutboundQueries: limit,
				MaxInternalQueries: limit,
			})

			start := make(chan struct{})
			results := make([]error, attempts)
			var wg sync.WaitGroup
			wg.Add(attempts)
			for i := range attempts {
				go func() {
					defer wg.Done()
					<-start
					results[i] = ledger.Debit(tt.kind)
				}()
			}
			close(start)
			wg.Wait()

			var accepted, rejected uint32
			for _, err := range results {
				if err == nil {
					accepted++
					continue
				}
				rejected++
				if !errors.Is(err, ErrRecursionWorkLimit) {
					t.Errorf("rejection %v does not wrap ErrRecursionWorkLimit", err)
				}
				var limitErr *RecursionWorkLimitError
				if !errors.As(err, &limitErr) {
					t.Errorf("rejection type = %T, want *RecursionWorkLimitError", err)
					continue
				}
				if limitErr.Kind != tt.kind || limitErr.Limit != limit {
					t.Errorf("rejection = {Kind:%v Limit:%d}, want {Kind:%v Limit:%d}",
						limitErr.Kind, limitErr.Limit, tt.kind, limit)
				}
			}

			if accepted != limit {
				t.Fatalf("accepted = %d, want exact cap %d", accepted, limit)
			}
			if rejected != attempts-limit {
				t.Fatalf("rejected = %d, want %d", rejected, attempts-limit)
			}

			snapshot := ledger.Snapshot()
			switch tt.kind {
			case RecursionWorkOutboundQuery:
				if snapshot.OutboundQueries != limit || !snapshot.OutboundExhausted {
					t.Fatalf("outbound snapshot = count:%d exhausted:%v, want count:%d exhausted:true",
						snapshot.OutboundQueries, snapshot.OutboundExhausted, limit)
				}
				if snapshot.InternalQueries != 0 || snapshot.InternalExhausted {
					t.Fatalf("unselected internal dimension changed: count:%d exhausted:%v",
						snapshot.InternalQueries, snapshot.InternalExhausted)
				}
			case RecursionWorkInternalQuery:
				if snapshot.InternalQueries != limit || !snapshot.InternalExhausted {
					t.Fatalf("internal snapshot = count:%d exhausted:%v, want count:%d exhausted:true",
						snapshot.InternalQueries, snapshot.InternalExhausted, limit)
				}
				if snapshot.OutboundQueries != 0 || snapshot.OutboundExhausted {
					t.Fatalf("unselected outbound dimension changed: count:%d exhausted:%v",
						snapshot.OutboundQueries, snapshot.OutboundExhausted)
				}
			}

			var firstErr *RecursionWorkLimitError
			if !errors.As(ledger.EnforcementError(), &firstErr) {
				t.Fatal("EnforcementError did not return a RecursionWorkLimitError")
			}
			if firstErr.Kind != tt.kind || firstErr.Limit != limit {
				t.Fatalf("EnforcementError = {Kind:%v Limit:%d}, want {Kind:%v Limit:%d}",
					firstErr.Kind, firstErr.Limit, tt.kind, limit)
			}
		})
	}
}

func TestRecursionWorkFinishWaitsForRetainedAsyncWork(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 8,
		MaxInternalQueries: 8,
	})
	release, ok := ledger.Retain()
	if !ok || release == nil {
		t.Fatal("Retain failed for an active ledger")
	}

	ledger.finish()
	if ledger.finished.Load() {
		t.Fatal("ledger published before retained work completed")
	}
	if err := ledger.Debit(RecursionWorkOutboundQuery); err != nil {
		t.Fatalf("retained-work debit: %v", err)
	}

	release()
	release() // release is deliberately once-safe
	if !ledger.finished.Load() {
		t.Fatal("ledger did not publish after retained work completed")
	}
	if got := ledger.Snapshot().OutboundQueries; got != 1 {
		t.Fatalf("published outbound work = %d, want 1", got)
	}
	if nextRelease, retained := ledger.Retain(); retained || nextRelease != nil {
		t.Fatal("Retain succeeded after final publication")
	}
}

func TestRecursionWorkLimitErrorCarriesSentinelAndPolicyEDE(t *testing.T) {
	ledger := NewRecursionWorkLedger(RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 1,
		MaxInternalQueries: 1,
	})
	if err := ledger.Debit(RecursionWorkInternalQuery); err != nil {
		t.Fatalf("first debit: %v", err)
	}

	err := ledger.Debit(RecursionWorkInternalQuery)
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("error %v does not wrap ErrRecursionWorkLimit", err)
	}
	if err.Error() != RecursionWorkEDEText {
		t.Fatalf("error text = %q, want %q", err.Error(), RecursionWorkEDEText)
	}

	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkInternalQuery || limitErr.Limit != 1 {
		t.Fatalf("limit error = {Kind:%v Limit:%d}, want internal limit 1",
			limitErr.Kind, limitErr.Limit)
	}
	if got := limitErr.EDECode(); got != RecursionWorkEDECode {
		t.Fatalf("EDECode = %d, want Other (%d)",
			got, RecursionWorkEDECode)
	}

	code, text := dnsutil.ErrorToEDE(err)
	if code != RecursionWorkEDECode {
		t.Fatalf("ErrorToEDE code = %d, want Other (%d)",
			code, RecursionWorkEDECode)
	}
	if text != RecursionWorkEDEText {
		t.Fatalf("ErrorToEDE text = %q, want %q", text, RecursionWorkEDEText)
	}
}

func TestChainRootAndNestedShareRecursionWorkLedger(t *testing.T) {
	rootPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 9,
		MaxInternalQueries: 7,
	}
	nestedPolicy := RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 1,
		MaxInternalQueries: 1,
	}

	var (
		rootLedger   *RecursionWorkLedger
		nestedLedger *RecursionWorkLedger
		rootMeta     *ResponseMeta
		nestedMeta   *ResponseMeta
	)

	nested := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		nestedLedger = RecursionWorkFrom(ctx)
		nestedMeta = ResponseMetaFrom(ctx)
		if err := DebitRecursionWork(ctx, RecursionWorkOutboundQuery); err != nil {
			t.Fatalf("nested outbound debit: %v", err)
		}
	})}, nestedPolicy)

	root := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		rootLedger = RecursionWorkFrom(ctx)
		rootMeta = ResponseMetaFrom(ctx)

		nested.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
		nested.Next(ctx)
	})}, rootPolicy)

	root.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	root.Next(context.Background())

	if rootLedger == nil || nestedLedger == nil {
		t.Fatalf("ledgers = root:%p nested:%p, want both non-nil", rootLedger, nestedLedger)
	}
	if nestedLedger != rootLedger {
		t.Fatalf("nested ledger %p != root ledger %p", nestedLedger, rootLedger)
	}
	if rootMeta != &root.Meta || nestedMeta != rootMeta {
		t.Fatalf("metadata pointers = root:%p nested:%p root backing:%p",
			rootMeta, nestedMeta, &root.Meta)
	}
	if got := nested.Meta.RecursionWork(); got != nil {
		t.Fatalf("nested chain installed its own ledger %p, want inherited root ledger only", got)
	}

	snapshot := rootLedger.Snapshot()
	if snapshot.Mode != RecursionWorkEnforce ||
		snapshot.MaxOutboundQueries != rootPolicy.MaxOutboundQueries ||
		snapshot.MaxInternalQueries != rootPolicy.MaxInternalQueries {
		t.Fatalf("nested policy replaced first policy: snapshot = %+v", snapshot)
	}
	if snapshot.OutboundQueries != 1 {
		t.Fatalf("shared outbound count = %d, want 1", snapshot.OutboundQueries)
	}
	if !rootLedger.finished.Load() {
		t.Fatal("outer Chain did not publish the request-tree completion")
	}
}

func TestChainResetKeepsPinnedLedgerIsolatedFromReuse(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkShadow,
		MaxOutboundQueries: 8,
		MaxInternalQueries: 8,
	}

	var contexts []context.Context
	ch := newChain([]Handler{HandlerFunc(func(ctx context.Context, _ *Chain) {
		contexts = append(contexts, ctx)
	})}, policy)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(context.Background())
	if len(contexts) != 1 {
		t.Fatalf("first request captured %d contexts, want 1", len(contexts))
	}
	oldCtx := contexts[0]
	oldLedger := RecursionWorkFrom(oldCtx)
	if oldLedger == nil {
		t.Fatal("first request did not establish a ledger")
	}

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), recursionWorkTestRequest())
	ch.Next(context.Background())
	if len(contexts) != 2 {
		t.Fatalf("second request captured %d contexts total, want 2", len(contexts))
	}
	newCtx := contexts[1]
	newLedger := RecursionWorkFrom(newCtx)
	if newLedger == nil {
		t.Fatal("second request did not establish a ledger")
	}
	if newLedger == oldLedger {
		t.Fatalf("pooled Chain reused old ledger %p for the next request", oldLedger)
	}

	if got := RecursionWorkFrom(oldCtx); got != oldLedger {
		t.Fatalf("old pinned context resolved ledger %p after Reset, want %p", got, oldLedger)
	}
	if got := ResponseMetaFrom(oldCtx).RecursionWork(); got != newLedger {
		t.Fatalf("pooled ResponseMeta now points to %p, want new ledger %p", got, newLedger)
	}

	if err := DebitRecursionWork(oldCtx, RecursionWorkOutboundQuery); err != nil {
		t.Fatalf("old-context debit: %v", err)
	}
	if err := DebitRecursionWork(newCtx, RecursionWorkInternalQuery); err != nil {
		t.Fatalf("new-context debit: %v", err)
	}

	oldSnapshot := oldLedger.Snapshot()
	if oldSnapshot.OutboundQueries != 1 || oldSnapshot.InternalQueries != 0 {
		t.Fatalf("old ledger counts = outbound:%d internal:%d, want outbound:1 internal:0",
			oldSnapshot.OutboundQueries, oldSnapshot.InternalQueries)
	}
	newSnapshot := newLedger.Snapshot()
	if newSnapshot.OutboundQueries != 0 || newSnapshot.InternalQueries != 1 {
		t.Fatalf("new ledger counts = outbound:%d internal:%d, want outbound:0 internal:1",
			newSnapshot.OutboundQueries, newSnapshot.InternalQueries)
	}
}

func TestPipelineQueryerDebitsInternalWorkAndRejectsAtCap(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 4,
		MaxInternalQueries: 1,
	}

	calls := 0
	handler := HandlerFunc(func(_ context.Context, ch *Chain) {
		calls++
		reply := new(dns.Msg)
		reply.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(reply)
	})
	pipe := newPipeline(
		[]Handler{handler},
		map[string]Handler{handler.Name(): handler},
		[]string{handler.Name()},
		policy,
	)
	queryer := NewPipelineQueryer(pipe)
	ctx, ledger := EnsureRecursionWork(context.Background(), policy)
	req := recursionWorkTestRequest()

	resp, err := queryer.Query(ctx, req)
	if err != nil {
		t.Fatalf("first Query: %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("first Query response = %#v, want successful DNS message", resp)
	}
	if calls != 1 {
		t.Fatalf("handler calls after first Query = %d, want 1", calls)
	}
	if got := ledger.Snapshot().InternalQueries; got != 1 {
		t.Fatalf("internal count after first Query = %d, want 1", got)
	}

	resp, err = queryer.Query(ctx, req)
	if resp != nil {
		t.Fatalf("rejected Query response = %#v, want nil", resp)
	}
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("rejected Query error = %v, want ErrRecursionWorkLimit", err)
	}
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("rejected Query error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkInternalQuery || limitErr.Limit != 1 {
		t.Fatalf("rejected Query error = {Kind:%v Limit:%d}, want internal limit 1",
			limitErr.Kind, limitErr.Limit)
	}
	if calls != 1 {
		t.Fatalf("handler calls after rejected Query = %d, want 1", calls)
	}
	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != 1 || !snapshot.InternalExhausted {
		t.Fatalf("internal snapshot after rejection = count:%d exhausted:%v, want count:1 exhausted:true",
			snapshot.InternalQueries, snapshot.InternalExhausted)
	}
}

func TestPipelineQueryerPropagatesEnforcementAfterSubPipeline(t *testing.T) {
	policy := RecursionWorkPolicy{
		Mode:               RecursionWorkEnforce,
		MaxOutboundQueries: 0,
		MaxInternalQueries: 2,
	}

	calls := 0
	handler := HandlerFunc(func(ctx context.Context, ch *Chain) {
		calls++
		_ = DebitRecursionWork(ctx, RecursionWorkOutboundQuery)
		reply := new(dns.Msg)
		reply.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(reply)
	})
	pipe := newPipeline(
		[]Handler{handler},
		map[string]Handler{handler.Name(): handler},
		[]string{handler.Name()},
		policy,
	)
	queryer := NewPipelineQueryer(pipe)
	ctx, ledger := EnsureRecursionWork(context.Background(), policy)

	resp, err := queryer.Query(ctx, recursionWorkTestRequest())
	if resp != nil {
		t.Fatalf("response = %#v, want nil when sub-pipeline exhausts enforcement", resp)
	}
	if !errors.Is(err, ErrRecursionWorkLimit) {
		t.Fatalf("Query error = %v, want ErrRecursionWorkLimit", err)
	}
	var limitErr *RecursionWorkLimitError
	if !errors.As(err, &limitErr) {
		t.Fatalf("Query error type = %T, want *RecursionWorkLimitError", err)
	}
	if limitErr.Kind != RecursionWorkOutboundQuery || limitErr.Limit != 0 {
		t.Fatalf("Query error = {Kind:%v Limit:%d}, want outbound limit 0",
			limitErr.Kind, limitErr.Limit)
	}
	if calls != 1 {
		t.Fatalf("handler calls = %d, want 1", calls)
	}
	snapshot := ledger.Snapshot()
	if snapshot.InternalQueries != 1 || snapshot.OutboundQueries != 0 || !snapshot.OutboundExhausted {
		t.Fatalf("snapshot = %+v, want one internal debit and rejected outbound debit", snapshot)
	}
}

func recursionWorkTestRequest() *dns.Msg {
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	return req
}
