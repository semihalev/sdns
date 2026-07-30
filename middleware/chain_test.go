package middleware

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/stretchr/testify/assert"
)

func TestResponseMeta_ConcurrentBoundCut(t *testing.T) {
	var meta ResponseMeta
	base := time.Now()
	earliest := base.Add(time.Second)
	const earliestKey = uint64(0xfeed)

	deadlines := make([]time.Time, 128)
	for i := range deadlines {
		deadlines[i] = base.Add(time.Duration(i+2) * time.Second)
	}
	deadlines[len(deadlines)/2] = earliest

	var wg sync.WaitGroup
	for i, deadline := range deadlines {
		deadline := deadline
		key := uint64(i + 1)
		if deadline.Equal(earliest) {
			key = earliestKey
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			meta.BoundCutFor(deadline, key)
		}()
	}
	wg.Wait()

	if got := meta.CutUntil(); !got.Equal(earliest) {
		t.Fatalf("CutUntil = %v, want earliest concurrent deadline %v", got, earliest)
	}
	if got := meta.CutKey(); got != earliestKey {
		t.Fatalf("CutKey = %#x, want earliest cut key %#x", got, earliestKey)
	}

	meta.Reset()
	if got := meta.CutUntil(); !got.IsZero() {
		t.Fatalf("CutUntil after Reset = %v, want zero", got)
	}
	if got := meta.CutKey(); got != 0 {
		t.Fatalf("CutKey after Reset = %#x, want zero", got)
	}
}

func TestValidatedDenialResponseIdentityAndExplicitTrust(t *testing.T) {
	t.Parallel()

	var meta ResponseMeta
	ctx := WithResponseMeta(context.Background(), &meta)
	marked := new(dns.Msg)
	marked.SetRcode(&dns.Msg{
		MsgHdr: dns.MsgHdr{Id: 1},
		Question: []dns.Question{{
			Name:   "Missing.Example.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		}},
	}, dns.RcodeNameError)
	marked.AuthenticatedData = false
	forgedProof := marked.Copy()

	MarkValidatedDenialResponse(ctx, marked, ValidatedDenial{
		DeniedName: "Missing.Example",
		Zone:       "Example",
		Proof:      forgedProof,
	})

	got, ok := ValidatedDenialForResponse(ctx, marked)
	if !ok {
		t.Fatal("exact NXDOMAIN response lost validated denial provenance")
	}
	want := ValidatedDenial{
		DeniedName: "missing.example.",
		Zone:       "example.",
		Proof:      marked,
	}
	if got != want {
		t.Fatalf("validated denial = %#v, want canonical %#v", got, want)
	}

	// Mark establishes immutable provenance once. Neither a caller-supplied
	// proof pointer nor a later conflicting mark can replace its source.
	MarkValidatedDenialResponse(ctx, marked, ValidatedDenial{
		DeniedName: "different.example.",
		Zone:       "different.example.",
	})
	if reread, rereadOK := ValidatedDenialForResponse(ctx, marked); !rereadOK || reread != want {
		t.Fatalf("second mark replaced immutable validated denial: %#v, %v", reread, rereadOK)
	}

	// The returned value is a copy: mutating it cannot alter the immutable
	// metadata held by ResponseMeta.
	got.Zone = "changed.example."
	if reread, rereadOK := ValidatedDenialForResponse(ctx, marked); !rereadOK || reread != want {
		t.Fatalf("stored validated denial changed through returned value: %#v, %v", reread, rereadOK)
	}

	if copied, copiedOK := ValidatedDenialForResponse(ctx, marked.Copy()); copiedOK {
		t.Fatalf("copied response inherited exact-response provenance: %#v", copied)
	}

	adOnly := marked.Copy()
	adOnly.AuthenticatedData = true
	if denial, adOnlyOK := ValidatedDenialForResponse(ctx, adOnly); adOnlyOK {
		t.Fatalf("unmarked AD response was treated as locally validated: %#v", denial)
	}
}

func TestValidatedDenialResponseConcurrentMessages(t *testing.T) {
	t.Parallel()

	const messageCount = 128
	var meta ResponseMeta
	ctx := WithResponseMeta(context.Background(), &meta)
	messages := make([]*dns.Msg, messageCount)

	var wg sync.WaitGroup
	for i := range messages {
		i := i
		messages[i] = new(dns.Msg)
		messages[i].SetRcode(new(dns.Msg), dns.RcodeNameError)

		wg.Add(1)
		go func() {
			defer wg.Done()
			name := dns.Fqdn(fmt.Sprintf("missing-%d.example", i))
			MarkValidatedDenialResponse(ctx, messages[i], ValidatedDenial{
				DeniedName: name,
				Zone:       "example.",
			})
			if got, ok := ValidatedDenialForResponse(ctx, messages[i]); !ok ||
				got.DeniedName != name || got.Zone != "example." || got.Proof != messages[i] {
				t.Errorf("message %d provenance = %#v, %v", i, got, ok)
			}
		}()
	}
	wg.Wait()

	for i, msg := range messages {
		wantName := dns.Fqdn(fmt.Sprintf("missing-%d.example", i))
		got, ok := ValidatedDenialForResponse(ctx, msg)
		if !ok || got.DeniedName != wantName || got.Zone != "example." || got.Proof != msg {
			t.Fatalf("message %d final provenance = %#v, %v", i, got, ok)
		}
	}
}

func TestPropagateValidatedDenialResponse(t *testing.T) {
	t.Parallel()

	var meta ResponseMeta
	ctx := WithResponseMeta(context.Background(), &meta)
	from := new(dns.Msg)
	from.SetRcode(new(dns.Msg), dns.RcodeNameError)
	to := from.Copy()
	denial := ValidatedDenial{
		DeniedName: "absent.child.example.",
		Zone:       "child.example.",
	}
	MarkValidatedDenialResponse(ctx, from, denial)

	if !PropagateValidatedDenialResponse(ctx, from, to) {
		t.Fatal("exact source provenance was not propagated")
	}
	got, ok := ValidatedDenialForResponse(ctx, to)
	if !ok || got.DeniedName != denial.DeniedName || got.Zone != denial.Zone {
		t.Fatalf("propagated provenance = %#v, %v; want names from %#v", got, ok, denial)
	}
	if got.Proof != from {
		t.Fatalf("propagation proof source = %p, want original validated response %p", got.Proof, from)
	}
	if got, ok := ValidatedDenialForResponse(ctx, to.Copy()); ok {
		t.Fatalf("copy of propagation target inherited provenance: %#v", got)
	}

	conflictingSource := from.Copy()
	MarkValidatedDenialResponse(ctx, conflictingSource, ValidatedDenial{
		DeniedName: "other.child.example.",
		Zone:       "child.example.",
	})
	if PropagateValidatedDenialResponse(ctx, conflictingSource, to) {
		t.Fatal("conflicting propagation replaced immutable target provenance")
	}
	if got, ok := ValidatedDenialForResponse(ctx, to); !ok || got.Proof != from {
		t.Fatalf("conflicting propagation changed target provenance: %#v, %v", got, ok)
	}

	unmarked := from.Copy()
	other := from.Copy()
	if PropagateValidatedDenialResponse(ctx, unmarked, other) {
		t.Fatal("unmarked source unexpectedly propagated provenance")
	}
	if got, ok := ValidatedDenialForResponse(ctx, other); ok {
		t.Fatalf("target of failed propagation was marked: %#v", got)
	}
}

func TestValidatedDenialResponseReset(t *testing.T) {
	t.Parallel()

	var meta ResponseMeta
	ctx := WithResponseMeta(context.Background(), &meta)
	oldResponse := new(dns.Msg)
	oldResponse.SetRcode(new(dns.Msg), dns.RcodeNameError)
	MarkValidatedDenialResponse(ctx, oldResponse, ValidatedDenial{
		DeniedName: "old.example.",
		Zone:       "example.",
	})
	if _, ok := ValidatedDenialForResponse(ctx, oldResponse); !ok {
		t.Fatal("precondition: old request provenance is absent")
	}

	meta.Reset()
	if got, ok := ValidatedDenialForResponse(ctx, oldResponse); ok {
		t.Fatalf("Reset retained old request provenance: %#v", got)
	}

	newResponse := oldResponse.Copy()
	MarkValidatedDenialResponse(ctx, newResponse, ValidatedDenial{
		DeniedName: "new.example.",
		Zone:       "example.",
	})
	if got, ok := ValidatedDenialForResponse(ctx, newResponse); !ok ||
		got.DeniedName != "new.example." {
		t.Fatalf("new request provenance after Reset = %#v, %v", got, ok)
	}
	if got, ok := ValidatedDenialForResponse(ctx, oldResponse); ok {
		t.Fatalf("new request mark revived old response provenance: %#v", got)
	}
}

func Test_Chain(t *testing.T) {
	w := mock.NewWriter("tcp", "127.0.0.1:0")
	ch := NewChain([]Handler{&dummy{}})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)
	req.SetEdns0(512, true)
	ch.Reset(w, req)

	ch.Next(context.Background())

	req.Rcode = dns.RcodeSuccess
	err := ch.Writer.WriteMsg(req)
	assert.NoError(t, err)

	data, err := req.Pack()
	assert.NoError(t, err)

	assert.Equal(t, true, ch.Writer.Written())
	assert.Equal(t, dns.RcodeSuccess, ch.Writer.Rcode())

	_, err = ch.Writer.Write(data)
	assert.Equal(t, errAlreadyWritten, err)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)
	size, err := ch.Writer.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), size)
	assert.NotNil(t, ch.Writer.Msg())

	err = ch.Writer.WriteMsg(req)
	assert.Equal(t, errAlreadyWritten, err)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)
	_, err = ch.Writer.Write([]byte{})
	assert.Error(t, err)

	assert.Equal(t, "tcp", ch.Writer.Proto())
	assert.Equal(t, "127.0.0.1", ch.Writer.RemoteIP().String())

	ch.Cancel()
	assert.Equal(t, 0, ch.count)

	ch.Reset(mock.NewWriter("tcp", "127.0.0.1:0"), req)

	ch.CancelWithRcode(dns.RcodeServerFailure, true)
	assert.True(t, ch.Writer.Written())
	assert.Equal(t, dns.RcodeServerFailure, ch.Writer.Rcode())
	assert.Equal(t, 0, ch.count)
}
