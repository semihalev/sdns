package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
)

func Test_Run(t *testing.T) {
	a := New(&config.Config{})
	a.Run(context.Background())
}

var setupBlocklist sync.Once

// newTestAPI returns an API over the pipeline's blocklist, with the given
// bearer token.
func newTestAPI(t *testing.T, token string) *API {
	t.Helper()
	setupBlocklist.Do(func() {
		cfg := new(config.Config)
		cfg.Nullroute = "0.0.0.0"
		cfg.Nullroutev6 = "::0"
		cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp")
		middleware.Register("blocklist", func(cfg *config.Config) middleware.Handler { return blocklist.New(cfg) })
		middleware.Setup(cfg)
	})
	a := New(&config.Config{BearerToken: token})
	if a.blocklist == nil {
		t.Fatal("no blocklist in the pipeline")
	}
	return a
}

func call(h http.Handler, method, target, body string, header map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range header {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestAPICalls(t *testing.T) {
	a := newTestAPI(t, "")
	h := a.handler()
	a.blocklist.Remove("api-test.com")

	for _, c := range []struct {
		method, target, body string
		code                 int
		want                 string
	}{
		{"GET", "/api/v1/block/set/api-test.com", "", 200, `{"success":true}`},
		{"GET", "/api/v1/block/get/api-test.com", "", 200, `{"success":true}`},
		{"GET", "/api/v1/block/get/missing.api-test.org", "", 404, `{"error":"missing.api-test.org not found"}`},
		{"GET", "/api/v1/block/exists/api-test.com", "", 200, `{"exists":true}`},
		{"GET", "/api/v1/block/remove/api-test.com", "", 200, `{"success":true}`},
		{"GET", "/api/v1/block/exists/api-test.com", "", 200, `{"exists":false}`},
		{"POST", "/api/v1/block/set/batch", `{"keys":["a.api-test.com","b.api-test.com"]}`, 200, `{"added":2,"requested":2,"skipped":0}`},
		{"POST", "/api/v1/block/remove/batch", `{"keys":["a.api-test.com","c.api-test.com"]}`, 200, `{"missing":1,"removed":1,"requested":2}`},
		{"POST", "/api/v1/block/remove/batch", `{"keys":[]}`, 400, `{"error":"keys is required and must be non-empty"}`},
		{"POST", "/api/v1/block/set/batch", `{"names":["x"]}`, 400, `invalid request body`},
		{"GET", "/api/v1/purge/api-test.com/a", "", 200, `{"success":true}`},
		{"GET", "/api/v1/purge/api-test.com/FOO", "", 400, `{"error":"unknown qtype: FOO"}`},
		{"GET", "/metrics", "", 200, "# HELP"},
		{"GET", "/notfound", "", 404, "404 page not found"},
		{"POST", "/api/v1/block/set/api-test.com", "", 405, ""},
	} {
		w := call(h, c.method, c.target, c.body, nil)
		if w.Code != c.code || !strings.Contains(w.Body.String(), c.want) {
			t.Errorf("%s %s = %d %q, want %d %q", c.method, c.target, w.Code, w.Body.String(), c.code, c.want)
		}
		if w.Header().Get("Server") != "sdns" || w.Header().Get("Pragma") != "no-cache" {
			t.Errorf("%s %s: response headers %v", c.method, c.target, w.Header())
		}
		// Nothing grants another site a read of what this listener says.
		if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("%s %s: Access-Control-Allow-Origin %q", c.method, c.target, got)
		}
	}
}

// Every route but pprof needs the token when one is configured, and only
// the exact "Bearer <token>" passes.
func TestAuthorization(t *testing.T) {
	const token = "secret_token"
	h := newTestAPI(t, token).handler()

	for _, target := range []string{
		"/api/v1/block/set/auth.test", "/api/v1/block/get/auth.test",
		"/api/v1/block/exists/auth.test", "/api/v1/block/remove/auth.test",
		"/api/v1/purge/auth.test/A", "/metrics",
	} {
		for _, auth := range []string{"", token, "Bearer", "Bearer ", "Bearer secret", "Bearer secret_token_", "bearer " + token, "Basic " + token} {
			w := call(h, "GET", target, "", map[string]string{"Authorization": auth})
			if w.Code != http.StatusUnauthorized || w.Body.String() != `{"error":"unauthorized"}` {
				t.Errorf("%s with %q = %d %q, want 401", target, auth, w.Code, w.Body.String())
			}
		}
		if w := call(h, "GET", target, "", map[string]string{"Authorization": "Bearer " + token}); w.Code == http.StatusUnauthorized {
			t.Errorf("%s refused the right token", target)
		}
	}
	for _, target := range []string{"/api/v1/block/set/batch", "/api/v1/block/remove/batch"} {
		if w := call(h, "POST", target, `{"keys":["auth.test"]}`, nil); w.Code != http.StatusUnauthorized {
			t.Errorf("POST %s without the token = %d, want 401", target, w.Code)
		}
	}
}

// A state-changing request a browser sends on behalf of another site is
// refused, and changes nothing; the same request from curl, from the
// user's own address bar or from a page this listener served goes through.
// Reads are not refused: without a CORS grant the other site cannot see
// what they return.
func TestCrossSiteChangesAreRefused(t *testing.T) {
	a := newTestAPI(t, "")
	h := a.handler()

	crossSite := []map[string]string{
		{"Sec-Fetch-Site": "cross-site"},
		{"Sec-Fetch-Site": "same-site"},
		{"Origin": "https://evil.example"},
		{"Origin": "http://127.0.0.1:3000"},
		{"Origin": "null"},
		{"Sec-Fetch-Site": "same-origin", "Origin": "https://evil.example"},
	}
	allowed := []map[string]string{
		nil,
		{"Sec-Fetch-Site": "none"},
		{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"},
	}

	changes := []struct{ method, target, body string }{
		{"GET", "/api/v1/block/set/csrf.test", ""},
		{"GET", "/api/v1/block/remove/csrf.test", ""},
		{"POST", "/api/v1/block/set/batch", `{"keys":["csrf.test"]}`},
		{"POST", "/api/v1/block/remove/batch", `{"keys":["csrf.test"]}`},
		{"GET", "/api/v1/purge/csrf.test/A", ""},
	}
	for _, c := range changes {
		for _, hdr := range crossSite {
			a.blocklist.Remove("csrf.test")
			w := call(h, c.method, c.target, c.body, hdr)
			if w.Code != http.StatusForbidden {
				t.Errorf("%s %s with %v = %d %q, want 403", c.method, c.target, hdr, w.Code, w.Body.String())
			}
			if a.blocklist.Exists("csrf.test") {
				t.Errorf("%s %s with %v changed the blocklist", c.method, c.target, hdr)
			}
		}
		for _, hdr := range allowed {
			if w := call(h, c.method, c.target, c.body, hdr); w.Code != http.StatusOK {
				t.Errorf("%s %s with %v = %d %q, want 200", c.method, c.target, hdr, w.Code, w.Body.String())
			}
		}
	}
	a.blocklist.Remove("csrf.test")

	for _, target := range []string{"/api/v1/block/exists/csrf.test", "/metrics"} {
		if w := call(h, "GET", target, "", map[string]string{"Sec-Fetch-Site": "cross-site"}); w.Code != http.StatusOK {
			t.Errorf("read %s from another site = %d, want 200", target, w.Code)
		}
	}
}

// pprof is served only with SDNS_PPROF, and outside the token: the tooling
// sends no Authorization header.
func TestPprofRoutes(t *testing.T) {
	saved := debugpprof
	defer func() { debugpprof = saved }()

	debugpprof = false
	if w := call(newTestAPI(t, "").handler(), "GET", "/debug/pprof/", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("pprof off: /debug/pprof/ = %d, want 404", w.Code)
	}

	debugpprof = true
	h := newTestAPI(t, "secret_token").handler()
	for target, code := range map[string]int{
		"/debug/":                    http.StatusMovedPermanently,
		"/debug/pprof/":              http.StatusOK,
		"/debug/pprof/goroutine":     http.StatusOK,
		"/debug/pprof/goroutineleak": http.StatusOK,
		"/debug/pprof/cmdline":       http.StatusOK,
		"/debug/pprof/symbol":        http.StatusOK,
		"/debug/pprof/no-such-prof":  http.StatusNotFound,
	} {
		if w := call(h, "GET", target, "", nil); w.Code != code {
			t.Errorf("%s = %d, want %d", target, w.Code, code)
		}
	}
	if w := call(h, "GET", "/debug/pprof/", "", nil); !strings.Contains(w.Body.String(), "goroutineleak") {
		t.Error("the index does not list goroutineleak")
	}
	// go tool pprof posts program counters to symbol.
	if w := call(h, "POST", "/debug/pprof/symbol", "0x0", nil); w.Code != http.StatusOK {
		t.Errorf("POST /debug/pprof/symbol = %d, want 200", w.Code)
	}
}

// A handler that panics answers 500 and leaves the listener serving.
func TestPanicIsRecovered(t *testing.T) {
	a := New(&config.Config{})
	a.metricsHandler = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") })
	h := a.handler()
	if w := call(h, "GET", "/metrics", "", nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("panicking handler = %d, want 500", w.Code)
	}
	if w := call(h, "GET", "/notfound", "", nil); w.Code != http.StatusNotFound {
		t.Fatalf("after a panic = %d, want the listener still serving", w.Code)
	}
}
