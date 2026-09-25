package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"net/url"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/internal/debugenv"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/zlog/v2"
)

// maxBlockBatchBody caps the JSON body for bulk block APIs so a
// hostile or accidental client can't pin the API server with an
// unbounded request.
const maxBlockBatchBody = 8 << 20 // 8 MiB

// blockBatchRequest is the wire format for POST /api/v1/block/{set,remove}/batch.
type blockBatchRequest struct {
	Keys []string `json:"keys"`
}

// responseHeaders go on every response. There is no CORS grant: a page on
// another site has no business reading what this listener answers, the
// metrics least of all, which name the domains clients asked for. The
// slices are shared, never written: a handler that sets one of these keys
// replaces the slice rather than writing into it.
var responseHeaders = http.Header{
	"Server":        {"sdns"},
	"Cache-Control": {"no-cache, no-store, no-transform, must-revalidate, private, max-age=0"},
	"Pragma":        {"no-cache"},
}

// API type.
type API struct {
	addr        string
	bearerToken string
	blocklist   *blocklist.BlockList
	// metricsHandler is built once: promhttp.Handler() constructed a new
	// instrumented handler per call, fresh collectors and a registry
	// registration attempt per scrape, and its gzip writers, though
	// pooled, were drained by GC between scrapes on a busy heap, so each
	// scrape paid a ~34KB deflate window in practice; together 1% of
	// process allocation under a frequent scraper. Compression stays off:
	// metrics text is small and scraped locally. Deliberate delta: the
	// promhttp_metric_handler_* self-instrumentation series are gone.
	metricsHandler http.Handler
}

var debugpprof = debugenv.PProf()

// New return new api.
func New(cfg *config.Config) *API {
	var bl *blocklist.BlockList

	b := middleware.Get("blocklist")
	if b != nil {
		bl = b.(*blocklist.BlockList)
	}

	return &API{
		addr:      cfg.API,
		blocklist: bl,
		metricsHandler: promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{
			DisableCompression: true,
		}),
		bearerToken: cfg.BearerToken,
	}
}

// handler builds the routes. A route guarded by auth needs the bearer
// token when one is configured; one guarded by change also refuses a
// request a browser sent on behalf of another site.
func (a *API) handler() http.Handler {
	mux := http.NewServeMux()

	// pprof tooling sends no Authorization header, so these routes are not
	// behind the token; they are served only when SDNS_PPROF is set. They
	// take any method, as net/http/pprof registers them: symbol reads its
	// counters from a POST body too. Index serves every named profile,
	// goroutineleak included, under /debug/pprof/<name>.
	if debugpprof {
		mux.HandleFunc("GET /debug/{$}", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/debug/pprof/", http.StatusMovedPermanently)
		})
		mux.HandleFunc("/debug/pprof/", pprof.Index)
		mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
		mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
		mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
		mux.HandleFunc("/debug/pprof/trace", pprof.Trace)
	}

	if a.blocklist != nil {
		mux.Handle("GET /api/v1/block/exists/{key}", a.auth(a.existsBlock))
		mux.Handle("GET /api/v1/block/get/{key}", a.auth(a.getBlock))
		mux.Handle("GET /api/v1/block/remove/{key}", a.auth(change(a.removeBlock)))
		mux.Handle("GET /api/v1/block/set/{key}", a.auth(change(a.setBlock)))
		mux.Handle("POST /api/v1/block/set/batch", a.auth(change(a.setBlockBatch)))
		mux.Handle("POST /api/v1/block/remove/batch", a.auth(change(a.removeBlockBatch)))
	}

	mux.Handle("GET /api/v1/purge/{qname}/{qtype}", a.auth(change(a.purge)))

	mux.Handle("GET /metrics", a.auth(a.metricsHandler.ServeHTTP))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				zlog.Error("Recovered in API", "recover", rec)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		h := w.Header()
		for k, v := range responseHeaders {
			h[k] = v
		}
		mux.ServeHTTP(w, r)
	})
}

// auth lets a request through when no token is configured or when it
// carries the token, compared in constant time.
func (a *API) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.bearerToken != "" {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(token), []byte(a.bearerToken)) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
				return
			}
		}
		next(w, r)
	})
}

// change refuses a state-changing request that a browser sent on behalf of
// another site: without a token, a page on the resolver's own machine could
// otherwise add to the blocklist or purge the cache through an image tag
// or a form. Browsers name the requesting site in Sec-Fetch-Site, and in
// Origin for anything but a plain navigation; curl and scripts send
// neither and are not affected.
func change(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if crossSite(r) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "cross-site request refused"})
			return
		}
		next(w, r)
	}
}

// crossSite reports a request a browser sent from another site. A request
// the user made directly, typed or bookmarked, is Sec-Fetch-Site none; one
// from a page this listener served is same-origin.
func crossSite(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "none", "same-origin":
	default:
		return true
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err != nil || u.Host != r.Host
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	buf, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// net/http commits headers on WriteHeader, so Content-Type
	// must be set first, otherwise the client sees whatever
	// default type net/http picks from the first bytes written.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(buf)
}

func (a *API) existsBlock(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"exists": a.blocklist.Exists(r.PathValue("key"))})
}

func (a *API) getBlock(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if ok, _ := a.blocklist.Get(key); !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": key + " not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (a *API) removeBlock(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"success": a.blocklist.Remove(r.PathValue("key"))})
}

func (a *API) setBlock(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"success": a.blocklist.Set(r.PathValue("key"))})
}

// readBatchKeys decodes a {"keys":[...]} JSON body, capped at
// maxBlockBatchBody. Returns the parsed keys or writes the
// appropriate 4xx response and returns nil.
func readBatchKeys(w http.ResponseWriter, r *http.Request) []string {
	r.Body = http.MaxBytesReader(w, r.Body, maxBlockBatchBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	var req blockBatchRequest
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body: " + err.Error()})
		return nil
	}
	if len(req.Keys) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "keys is required and must be non-empty"})
		return nil
	}
	return req.Keys
}

func (a *API) setBlockBatch(w http.ResponseWriter, r *http.Request) {
	keys := readBatchKeys(w, r)
	if keys == nil {
		return
	}
	added := a.blocklist.SetBatch(keys)
	writeJSON(w, http.StatusOK, map[string]any{
		"requested": len(keys),
		"added":     added,
		"skipped":   len(keys) - added,
	})
}

func (a *API) removeBlockBatch(w http.ResponseWriter, r *http.Request) {
	keys := readBatchKeys(w, r)
	if keys == nil {
		return
	}
	removed := a.blocklist.RemoveBatch(keys)
	writeJSON(w, http.StatusOK, map[string]any{
		"requested": len(keys),
		"removed":   removed,
		"missing":   len(keys) - removed,
	})
}

func (a *API) purge(w http.ResponseWriter, r *http.Request) {
	qtypeName := strings.ToUpper(r.PathValue("qtype"))
	qtype, ok := dns.StringToType[qtypeName]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unknown qtype: " + qtypeName})
		return
	}
	q := dns.Question{
		Name:   dns.Fqdn(r.PathValue("qname")),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}

	// Invalidate every purger the pipeline exposes, today that's
	// the cache middleware (positive + negative entries) and the
	// resolver handler (NS cache, TypeNS only). No synthesised
	// CHAOS-NULL query, no base64 encoding; just a direct call.
	for _, p := range middleware.GlobalPipeline().Purgers() {
		p.Purge(q)
	}

	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

// (*API).Run run API server.
func (a *API) Run(ctx context.Context) {
	if a.addr == "" {
		return
	}

	srv := &http.Server{
		Addr:              a.addr,
		Handler:           a.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zlog.Error("Start API server failed", "error", err.Error())
		}
	}()

	zlog.Info("API server listening...", "addr", a.addr)
	if a.bearerToken != "" {
		// Never log the token itself, anyone who can read process
		// or aggregated logs would be able to call the protected
		// endpoints (cache purge, blocklist mutation, metrics).
		zlog.Info("API bearer-token authorization enabled")
	}

	go func() { //nolint:gosec // G118 - intentionally using Background() for shutdown grace period after parent ctx is cancelled
		<-ctx.Done()

		zlog.Info("API server stopping...", "addr", a.addr)

		apiCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(apiCtx); err != nil {
			zlog.Error("Shutdown API server failed:", "error", err.Error())
		}
	}()
}
