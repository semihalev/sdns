package resolver

import (
	"context"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

// Test_checkLoop_DnameDepthNoCollision guards the context-key layout.
//
// checkLoop derives its key as contextKeyNSList + contextKey(qtype). When
// contextKeyNSList sat right below the fixed keys, an A query (qtype 1)
// produced the same key as contextKeyDnameDepth. After a DNAME was followed
// (which stores an int depth under contextKeyDnameDepth) the IPv4 NS lookup
// hit checkLoop, read that int, and panicked on v.([]string).
func Test_checkLoop_DnameDepthNoCollision(t *testing.T) {
	// checkLoop only reads ctx/qname/qtype, never the receiver.
	r := &Resolver{}

	// Simulate a DNAME having been followed: int depth under its key.
	ctx := context.WithValue(context.Background(), contextKeyDnameDepth, 3)

	// IPv4 NS lookup path: checkLoop with qtype A must not read that int
	// as a []string.
	if func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		ctx, _ = r.checkLoop(ctx, "ns1.example.com.", dns.TypeA)
		return
	}() {
		t.Error("checkLoop panicked")
	}

	// The DNAME depth is untouched — the two keys are distinct.
	depth, _ := ctx.Value(contextKeyDnameDepth).(int)
	if !reflect.DeepEqual(3, depth) {
		t.Errorf("depth = %v, want %v", depth, 3)
	}

	// Loop detection still works for A queries: a qname seen a third time
	// trips the guard.
	var loop bool
	ctx, loop = r.checkLoop(ctx, "ns1.example.com.", dns.TypeA)
	if loop {
		t.Errorf("loop is true")
	}
	_, loop = r.checkLoop(ctx, "ns1.example.com.", dns.TypeA)
	if !(loop) {
		t.Errorf("loop is false")
	}
}

// Test_checkLoop_KeyNoFixedCollision asserts that no qtype maps a derived
// NS-list key onto a fixed context key, so the int-vs-[]string class of bug
// cannot recur. The qtype is a 16-bit field, so we sweep the whole range.
func Test_checkLoop_KeyNoFixedCollision(t *testing.T) {
	fixed := map[contextKey]string{
		contextKeyRequestID:  "contextKeyRequestID",
		contextKeyNSL:        "contextKeyNSL",
		contextKeyDnameDepth: "contextKeyDnameDepth",
	}
	for qtype := 0; qtype <= 0xffff; qtype++ {
		key := contextKeyNSList + contextKey(qtype)
		if name, clash := fixed[key]; clash {
			t.Fatalf("NS-list key for qtype %d collides with %s", qtype, name)
		}
	}
}
