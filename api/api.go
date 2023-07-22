package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/pprof"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/nahojer/routes"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
)

// API type
type API struct {
	addr      string
	blocklist *blocklist.BlockList

	rt *routes.Trie[http.Handler]
}

type J map[string]any

type ctxKey string

var extraHeaders = map[string]string{
	"Server":                       "sdns",
	"Access-Control-Allow-Origin":  "*",
	"Access-Control-Allow-Methods": "GET,POST",
	"Cache-Control":                "no-cache, no-store, no-transform, must-revalidate, private, max-age=0",
	"Pragma":                       "no-cache",
}

var debugpprof bool

func init() {
	_, debugpprof = os.LookupEnv("SDNS_PPROF")
}

// New return new api
func New(cfg *config.Config) *API {
	var bl *blocklist.BlockList

	b := middleware.Get("blocklist")
	if b != nil {
		bl = b.(*blocklist.BlockList)
	}

	return &API{
		addr:      cfg.API,
		blocklist: bl,

		rt: routes.NewTrie[http.Handler](),
	}
}

func (a *API) existsBlock(w http.ResponseWriter, r *http.Request) {
	a.JSON(w, http.StatusOK, J{"exists": a.blocklist.Exists(a.Param(r, "key"))})
}

func (a *API) getBlock(w http.ResponseWriter, r *http.Request) {
	if ok, _ := a.blocklist.Get(a.Param(r, "key")); !ok {
		a.JSON(w, http.StatusNotFound, J{"error": a.Param(r, "key") + " not found"})
	} else {
		a.JSON(w, http.StatusOK, J{"success": ok})
	}
}

func (a *API) removeBlock(w http.ResponseWriter, r *http.Request) {
	a.JSON(w, http.StatusOK, J{"success": a.blocklist.Remove(a.Param(r, "key"))})
}

func (a *API) setBlock(w http.ResponseWriter, r *http.Request) {
	a.JSON(w, http.StatusOK, J{"success": a.blocklist.Set(a.Param(r, "key"))})
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	promhttp.Handler().ServeHTTP(w, r)
}

func (a *API) purge(w http.ResponseWriter, r *http.Request) {
	qtype := strings.ToUpper(a.Param(r, "qtype"))
	qname := dns.Fqdn(a.Param(r, "qname"))

	bqname := base64.StdEncoding.EncodeToString([]byte(qtype + ":" + qname))

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(bqname), dns.TypeNULL)
	req.Question[0].Qclass = dns.ClassCHAOS

	_, _ = dnsutil.ExchangeInternal(context.Background(), req)

	a.JSON(w, http.StatusOK, J{"success": true})
}

func (a *API) JSON(w http.ResponseWriter, code int, data any) {
	buf, err := json.Marshal(data)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	w.WriteHeader(code)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	_, _ = w.Write(buf)
}

func (a *API) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			log.Error("Recovered in API", "recover", r)

			_, _ = os.Stderr.WriteString(fmt.Sprintf("panic: %v\n\n", r))
			debug.PrintStack()
		}
	}()

	for k, v := range extraHeaders {
		w.Header().Set(k, v)
	}

	r, h := a.Match(r)
	if h == nil {
		http.NotFound(w, r)
		return
	}

	h.ServeHTTP(w, r)
}

func (a *API) Handle(method, path string, handle http.HandlerFunc) {
	a.rt.Add(method, path, handle)
}

func (a *API) GET(path string, handle http.HandlerFunc) {
	a.rt.Add(http.MethodGet, path, handle)
}

func (a *API) POST(path string, handle http.HandlerFunc) {
	a.rt.Add(http.MethodPost, path, handle)
}

func (a *API) Match(r *http.Request) (*http.Request, http.Handler) {
	h, params, ok := a.rt.Lookup(r)

	if !ok {
		return r, nil
	}

	for k, v := range params {
		ctx := context.WithValue(r.Context(), ctxKey(k), v)
		r = r.WithContext(ctx)
	}

	return r, h
}

func (a *API) Param(r *http.Request, key string) string {
	if v, ok := r.Context().Value(ctxKey(key)).(string); ok {
		return v
	}

	return ""
}

func (a *API) Group(rp string) *group {
	return &group{parent: a, path: rp}
}

type group struct {
	parent *API
	path   string
}

func (g *group) GET(path string, handle http.HandlerFunc) {
	g.parent.GET(g.path+path, handle)
}

func (g *group) POST(path string, handle http.HandlerFunc) {
	g.parent.POST(g.path+path, handle)
}

// Run API server
func (a *API) Run(ctx context.Context) {
	if a.addr == "" {
		return
	}

	if debugpprof {
		profiler := a.Group("/debug")
		{
			profiler.GET("/", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, profiler.path+"/pprof/", http.StatusMovedPermanently)
			})
			profiler.GET("/pprof/...", pprof.Index)
			profiler.GET("/pprof/cmdline", pprof.Cmdline)
			profiler.GET("/pprof/profile", pprof.Profile)
			profiler.GET("/pprof/symbol", pprof.Symbol)
			profiler.GET("/pprof/trace", pprof.Trace)

			profiler.GET("/pprof/goroutine", pprof.Handler("goroutine").ServeHTTP)
			profiler.GET("/pprof/threadcreate", pprof.Handler("threadcreate").ServeHTTP)
			profiler.GET("/pprof/mutex", pprof.Handler("mutex").ServeHTTP)
			profiler.GET("/pprof/heap", pprof.Handler("heap").ServeHTTP)
			profiler.GET("/pprof/block", pprof.Handler("block").ServeHTTP)
			profiler.GET("/pprof/allocs", pprof.Handler("allocs").ServeHTTP)
		}
	}

	if a.blocklist != nil {
		block := a.Group("/api/v1/block")
		{
			block.GET("/exists/:key", a.existsBlock)
			block.GET("/get/:key", a.getBlock)
			block.GET("/remove/:key", a.removeBlock)
			block.GET("/set/:key", a.setBlock)
		}
	}

	a.GET("/api/v1/purge/:qname/:qtype", a.purge)

	a.GET("/metrics", a.metrics)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: a,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Start API server failed", "error", err.Error())
		}
	}()

	log.Info("API server listening...", "addr", a.addr)

	go func() {
		<-ctx.Done()

		log.Info("API server stopping...", "addr", a.addr)

		apiCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := srv.Shutdown(apiCtx); err != nil {
			log.Error("Shutdown API server failed:", "error", err.Error())
		}
	}()
}
