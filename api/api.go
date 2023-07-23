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
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/dnsutil"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
)

// API type
type (
	API struct {
		addr      string
		blocklist *blocklist.BlockList

		get     Tree
		post    Tree
		delete  Tree
		put     Tree
		patch   Tree
		head    Tree
		connect Tree
		trace   Tree
		options Tree

		paramsPool sync.Pool
	}

	Group struct {
		parent *API
		path   string
	}

	Param struct {
		Key   string
		Value string
	}

	Params []Param

	ctxKey struct{}

	J map[string]any
)

var (
	extraHeaders = map[string]string{
		"Server":                       "sdns",
		"Access-Control-Allow-Origin":  "*",
		"Access-Control-Allow-Methods": "GET,POST",
		"Cache-Control":                "no-cache, no-store, no-transform, must-revalidate, private, max-age=0",
		"Pragma":                       "no-cache",
	}

	debugpprof bool

	CtxKey ctxKey
)

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

	a := &API{
		addr:      cfg.API,
		blocklist: bl,
	}

	a.paramsPool.New = func() interface{} {
		params := make(Params, 0, 20)
		return &params
	}

	return a
}

func (a *API) getParams() *Params {
	ps, _ := a.paramsPool.Get().(*Params)
	*ps = (*ps)[0:0]
	return ps
}

func (a *API) putParams(params *Params) {
	if params != nil {
		a.paramsPool.Put(params)
	}
}

func (a *API) selectTree(method string) *Tree {
	switch method {
	case http.MethodGet:
		return &a.get
	case http.MethodPost:
		return &a.post
	case http.MethodDelete:
		return &a.delete
	case http.MethodPut:
		return &a.put
	case http.MethodPatch:
		return &a.patch
	case http.MethodHead:
		return &a.head
	case http.MethodConnect:
		return &a.connect
	case http.MethodTrace:
		return &a.trace
	case http.MethodOptions:
		return &a.options
	default:
		return nil
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

	h, params := a.Match(r)

	if h == nil {
		http.NotFound(w, r)
		return
	}

	if params != nil {
		ctx := r.Context()
		ctx = context.WithValue(ctx, CtxKey, *params)
		r = r.WithContext(ctx)

		a.putParams(params)
	}

	h.ServeHTTP(w, r)

}

func (a *API) Handle(method, path string, handle http.HandlerFunc) {
	tree := a.selectTree(method)
	tree.Add(path, handle)
}

func (a *API) GET(path string, handle http.HandlerFunc) {
	a.get.Add(path, handle)
}

func (a *API) POST(path string, handle http.HandlerFunc) {
	a.post.Add(path, handle)
}

func (a *API) Match(r *http.Request) (http.Handler, *Params) {
	if r.Method[0] == 'G' {
		return a.get.Lookup(r.URL.Path, a.getParams)
	}

	tree := a.selectTree(r.Method)
	h, params := tree.Lookup(r.URL.Path, a.getParams)

	if h == nil {
		if params != nil {
			a.putParams(params)
		}
		return nil, nil
	}

	return h, params
}

func (a *API) Param(r *http.Request, key string) string {
	if params, ok := r.Context().Value(CtxKey).(Params); ok {
		for _, p := range params {
			if p.Key == key {
				return p.Value
			}
		}
	}

	return ""
}

func (a *API) Group(rp string) *Group {
	return &Group{parent: a, path: rp}
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
			profiler.GET("/pprof/", pprof.Index)
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

func (g *Group) GET(path string, handle http.HandlerFunc) {
	g.parent.GET(g.path+path, handle)
}

func (g *Group) POST(path string, handle http.HandlerFunc) {
	g.parent.POST(g.path+path, handle)
}

func (params *Params) addParameter(key, value string) {
	i := len(*params)
	*params = (*params)[:i+1]
	(*params)[i] = Param{
		Key:   key,
		Value: value,
	}
}
