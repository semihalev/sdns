package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
)

// A browser page that POSTs a DNS message sends a CORS preflight first,
// since application/dns-message is not a safelisted content type. The
// preflight must succeed, or the browser never sends the query.
func TestDoHAnswersThePreflight(t *testing.T) {
	cfg := &config.Config{BindDOH: config.Addrs{"127.0.0.1:443"}}
	reached := false
	s := serverWithHandler(cfg, middleware.HandlerFunc(func(context.Context, *middleware.Chain) {
		reached = true
	}))

	req := httptest.NewRequest(http.MethodOptions, "/dns-query", nil)
	req.Header.Set("Origin", "https://example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "content-type")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusNoContent)
	}
	h := w.Header()
	if got := h.Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want *", got)
	}
	methods := h.Get("Access-Control-Allow-Methods")
	if !strings.Contains(methods, "GET") || !strings.Contains(methods, "POST") {
		t.Errorf("Access-Control-Allow-Methods = %q, want GET and POST", methods)
	}
	if got := strings.ToLower(h.Get("Access-Control-Allow-Headers")); !strings.Contains(got, "content-type") {
		t.Errorf("Access-Control-Allow-Headers = %q, want content-type", got)
	}
	if w.Body.Len() != 0 {
		t.Errorf("body = %q, want empty", w.Body.String())
	}
	if reached {
		t.Error("a preflight reached the DNS pipeline")
	}
}
