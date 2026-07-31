package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/mock"
	"github.com/semihalev/sdns/middleware"
)

type serverContextKeyType struct{}

var serverContextKey = &serverContextKeyType{}

func serverWithHandler(cfg *config.Config, handler middleware.Handler) *Server {
	registry := middleware.NewRegistry()
	registry.Register("context-test", func(*config.Config) middleware.Handler {
		return handler
	})
	return &Server{cfg: cfg, pipeline: registry.Build(cfg)}
}

func TestServeDNSStartsQueryTimeoutAtIngress(t *testing.T) {
	cfg := &config.Config{QueryTimeout: config.Duration{Duration: 20 * time.Millisecond}}
	var (
		gotErr      error
		hadDeadline bool
	)
	handler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		_, hadDeadline = ctx.Deadline()
		<-ctx.Done()
		gotErr = ctx.Err()
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)

	req := new(dns.Msg)
	req.SetQuestion("timeout.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	done := make(chan struct{})
	go func() {
		s.ServeDNS(writer, req)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("request outlived the configured ingress query timeout")
	}
	if !hadDeadline {
		t.Fatal("pipeline context had no ingress deadline")
	}
	if gotErr != context.DeadlineExceeded {
		t.Fatalf("pipeline context error = %v, want deadline exceeded", gotErr)
	}
}

func TestServeDNSContextPreservesTransportCancellation(t *testing.T) {
	cfg := &config.Config{QueryTimeout: config.Duration{Duration: time.Second}}
	started := make(chan struct{})
	var gotValue any
	handler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		gotValue = ctx.Value(serverContextKey)
		close(started)
		<-ctx.Done()
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)

	parent, cancel := context.WithCancel(context.WithValue(
		context.Background(),
		serverContextKey,
		"transport",
	))
	req := new(dns.Msg)
	req.SetQuestion("cancel.example.", dns.TypeA)
	writer := mock.NewWriter("udp", "192.0.2.1:53000")
	done := make(chan struct{})
	go func() {
		s.ServeDNSContext(parent, writer, req)
		close(done)
	}()

	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("request did not enter pipeline")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("transport cancellation did not reach pipeline")
	}
	if gotValue != "transport" {
		t.Fatalf("transport context value = %v, want transport", gotValue)
	}
}

func TestServeHTTPPropagatesRequestContext(t *testing.T) {
	cfg := &config.Config{
		BindDOH:      "127.0.0.1:443",
		QueryTimeout: config.Duration{Duration: time.Second},
	}
	var gotValue any
	handler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		gotValue = ctx.Value(serverContextKey)
		resp := new(dns.Msg)
		resp.SetReply(ch.Request)
		_ = ch.Writer.WriteMsg(resp)
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=context.example&type=A", nil)
	req = req.WithContext(context.WithValue(req.Context(), serverContextKey, "doh"))
	writer := httptest.NewRecorder()
	s.ServeHTTP(writer, req)

	if writer.Code != http.StatusOK {
		t.Fatalf("DoH status = %d, want 200", writer.Code)
	}
	if gotValue != "doh" {
		t.Fatalf("DoH pipeline context value = %v, want doh", gotValue)
	}
}

func TestServeHTTPCanceledRequestDoesNotEmitBadRequest(t *testing.T) {
	cfg := &config.Config{
		BindDOH:      "127.0.0.1:443",
		QueryTimeout: config.Duration{Duration: time.Second},
	}
	called := false
	handler := middleware.HandlerFunc(func(ctx context.Context, ch *middleware.Chain) {
		called = true
		ch.Cancel()
	})
	s := serverWithHandler(cfg, handler)

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=cancel.example&type=A", nil)
	ctx, cancel := context.WithCancel(req.Context())
	cancel()
	req = req.WithContext(ctx)
	writer := httptest.NewRecorder()
	s.ServeHTTP(writer, req)

	if writer.Code == http.StatusBadRequest {
		t.Fatal("canceled DoH request was misreported as HTTP 400")
	}
	if writer.Body.Len() != 0 {
		t.Fatalf("canceled DoH request wrote an unexpected body: %q", writer.Body.String())
	}
	if called {
		t.Fatal("canceled DoH request entered the middleware pipeline")
	}
}
