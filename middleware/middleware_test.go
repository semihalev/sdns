package middleware

import (
	"context"
	"reflect"
	"sync"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
)

type dummy struct{}

func (d *dummy) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (d *dummy) Name() string                            { return "dummy" }

type namedHandler struct{ n string }

func (h *namedHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *namedHandler) Name() string                            { return h.n }

func Test_DefaultRegistry_Setup(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("dummy", func(*config.Config) Handler { return &dummy{} })

	if Get("dummy") != nil {
		t.Errorf("%s: Get('dummy') = %v, want nil", "Get before Setup must return nil", Get("dummy"))
	}
	if Ready() {
		t.Errorf("Ready() is true")
	}

	Setup(&config.Config{})

	if !(Ready()) {
		t.Errorf("Ready() is false")
	}
	if !func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		Setup(&config.Config{})
		return
	}() {
		t.Error("double Setup must panic")
	}

	if !reflect.DeepEqual([]string{"dummy"}, List()) {
		t.Errorf("List() = %v, want %v", List(), []string{"dummy"})
	}
	if !reflect.DeepEqual(1, len(Handlers())) {
		t.Errorf("len(Handlers()) = %v, want %v", len(Handlers()), 1)
	}

	d := Get("dummy")
	if d == nil {
		t.Error("d is nil")
	} else if !reflect.DeepEqual("dummy", d.Name()) {
		t.Errorf("d.Name() = %v, want %v", d.Name(), "dummy")
	}
	if Get("none") != nil {
		t.Errorf("Get('none') = %v, want nil", Get("none"))
	}
}

// Test_Get_SkipsDisabled guards against a regression where disabled
// middlewares shifted the Get() index lookup onto the next enabled handler.
func Test_Get_SkipsDisabled(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("first", func(*config.Config) Handler { return &namedHandler{n: "first"} })
	Register("disabled", func(*config.Config) Handler {
		var h *namedHandler // typed-nil => isNilHandler skips it
		return h
	})
	Register("second", func(*config.Config) Handler { return &namedHandler{n: "second"} })

	Setup(&config.Config{})

	if !reflect.DeepEqual(2, len(Handlers())) {
		t.Errorf("len(Handlers()) = %v, want %v", len(Handlers()), 2)
	}
	if !reflect.DeepEqual([]string{"first", "disabled", "second"}, List()) {
		t.Errorf("List() = %v, want %v", List(), []string{"first", "disabled", "second"})
	}

	if h := Get("first"); h == nil {
		t.Error("h is nil")
	} else if !reflect.DeepEqual("first", h.Name()) {
		t.Errorf("h.Name() = %v, want %v", h.Name(), "first")
	}
	if Get("disabled") != nil {
		t.Errorf("Get('disabled') = %v, want nil", Get("disabled"))
	}
	if h := Get("second"); h == nil {
		t.Error("h is nil")
	} else if !reflect.DeepEqual("second", h.Name()) {
		t.Errorf("h.Name() = %v, want %v", h.Name(), "second")
	}
}

func Test_Registry_RegisterAt(t *testing.T) {
	r := NewRegistry()

	r.Register("dummy", func(*config.Config) Handler { return &dummy{} })
	r.RegisterAt("dummy2", func(*config.Config) Handler { return &dummy{} }, 0)
	r.RegisterBefore("dummy3", func(*config.Config) Handler { return &dummy{} }, "dummy")

	if !reflect.DeepEqual([]string{"dummy2", "dummy3", "dummy"}, r.List()) {
		t.Errorf("r.List() = %v, want %v", r.List(), []string{"dummy2", "dummy3", "dummy"})
	}

	if !func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		r.RegisterAt("tooHigh", func(*config.Config) Handler { return &dummy{} }, 99)
		return
	}() {
		t.Error("RegisterAt above the end must panic")
	}
	if !func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		r.RegisterAt("tooLow", func(*config.Config) Handler { return &dummy{} }, -1)
		return
	}() {
		t.Error("RegisterAt below zero must panic")
	}
	if !func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		r.RegisterBefore("orphan", func(*config.Config) Handler { return &dummy{} }, "nope")
		return
	}() {
		t.Error("RegisterBefore an unknown name must panic")
	}
	if !func() (panicked bool) {
		defer func() { panicked = recover() != nil }()
		r.Register("dummy", func(*config.Config) Handler { return &dummy{} })
		return
	}() {
		t.Error("duplicate Register must panic")
	}
}

func Test_Registry_Build_ConcurrentReads(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("h", func(*config.Config) Handler { return &namedHandler{n: "h"} })
	Setup(&config.Config{})

	var wg sync.WaitGroup
	const readers = 16
	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			for range 1000 {
				_ = Handlers()
				_ = Get("h")
				_ = Ready()
			}
		}()
	}
	wg.Wait()
}

func Test_Pipeline_NilSafe(t *testing.T) {
	var p *Pipeline
	if p.Handlers() != nil {
		t.Errorf("p.Handlers() = %v, want nil", p.Handlers())
	}
	if p.Get("anything") != nil {
		t.Errorf("p.Get('anything') = %v, want nil", p.Get("anything"))
	}
	if p.List() != nil {
		t.Errorf("p.List() = %v, want nil", p.List())
	}
	if p.SubPipeline("x") != nil {
		t.Errorf("p.SubPipeline('x') = %v, want nil", p.SubPipeline("x"))
	}
	if p.NewChain() != nil {
		t.Errorf("p.NewChain() = %v, want nil", p.NewChain())
	}
	if p.Purgers() != nil {
		t.Errorf("p.Purgers() = %v, want nil", p.Purgers())
	}
}

// purgerHandler implements both Handler and Purger; used to verify
// Pipeline.Purgers enumerates only handlers implementing Purger.
type purgerHandler struct {
	n       string
	purgedQ []string
}

func (h *purgerHandler) ServeDNS(ctx context.Context, ch *Chain) { ch.Next(ctx) }
func (h *purgerHandler) Name() string                            { return h.n }
func (h *purgerHandler) Purge(q dns.Question)                    { h.purgedQ = append(h.purgedQ, q.Name) }

func Test_Pipeline_SubPipeline_FiltersByName(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("a", func(*config.Config) Handler { return &namedHandler{n: "a"} })
	Register("b", func(*config.Config) Handler { return &namedHandler{n: "b"} })
	Register("c", func(*config.Config) Handler { return &namedHandler{n: "c"} })

	Setup(&config.Config{})

	sub := GlobalPipeline().SubPipeline("b")
	if !reflect.DeepEqual(2, len(sub.Handlers())) {
		t.Errorf("len(sub.Handlers()) = %v, want %v", len(sub.Handlers()), 2)
	}
	if !reflect.DeepEqual("a", sub.Handlers()[0].Name()) {
		t.Errorf("sub.Handlers()[0].Name() = %v, want %v", sub.Handlers()[0].Name(), "a")
	}
	if !reflect.DeepEqual("c", sub.Handlers()[1].Name()) {
		t.Errorf("sub.Handlers()[1].Name() = %v, want %v", sub.Handlers()[1].Name(), "c")
	}
	if sub.Get("b") != nil {
		t.Errorf("%s: sub.Get('b') = %v, want nil", "filtered handler must not be reachable via Get", sub.Get("b"))
	}

	// Skipping a name that isn't in the pipeline is a no-op.
	sub2 := GlobalPipeline().SubPipeline("nope")
	if !reflect.DeepEqual(3, len(sub2.Handlers())) {
		t.Errorf("len(sub2.Handlers()) = %v, want %v", len(sub2.Handlers()), 3)
	}
}

func Test_Pipeline_NewChain_IsFreshPerCall(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	Register("a", func(*config.Config) Handler { return &namedHandler{n: "a"} })
	Setup(&config.Config{})

	p := GlobalPipeline()
	c1 := p.NewChain()
	c2 := p.NewChain()
	if c1 == nil {
		t.Fatalf("c1 is nil")
	}
	if c2 == nil {
		t.Fatalf("c2 is nil")
	}
	if c1 == c2 {
		t.Errorf("%s: %p is the same pointer", "each NewChain call must return a distinct instance", c1)
	}
}

func Test_Pipeline_Purgers_EnumeratesOnlyPurgerHandlers(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	p1 := &purgerHandler{n: "cache"}
	p2 := &purgerHandler{n: "resolver"}
	Register("cache", func(*config.Config) Handler { return p1 })
	Register("plain", func(*config.Config) Handler { return &namedHandler{n: "plain"} })
	Register("resolver", func(*config.Config) Handler { return p2 })

	Setup(&config.Config{})

	pp := GlobalPipeline().Purgers()
	if !reflect.DeepEqual(2, len(pp)) {
		t.Errorf("%s: len(pp) = %v, want %v", "non-Purger handlers must be excluded", len(pp), 2)
	}

	q := dns.Question{Name: "example.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET}
	for _, pr := range pp {
		pr.Purge(q)
	}
	if !reflect.DeepEqual([]string{"example.com."}, p1.purgedQ) {
		t.Errorf("p1.purgedQ = %v, want %v", p1.purgedQ, []string{"example.com."})
	}
	if !reflect.DeepEqual([]string{"example.com."}, p2.purgedQ) {
		t.Errorf("p2.purgedQ = %v, want %v", p2.purgedQ, []string{"example.com."})
	}
}
