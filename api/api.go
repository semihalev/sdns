package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
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
type API struct {
	addr      string
	router    *Router
	blocklist *blocklist.BlockList
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

	a := &API{
		addr:      cfg.API,
		blocklist: bl,
		router:    NewRouter(),
	}

	return a
}

func (a *API) existsBlock(ctx *Context) {
	ctx.JSON(http.StatusOK, Json{"exists": a.blocklist.Exists(ctx.Param("key"))})
}

func (a *API) getBlock(ctx *Context) {
	if ok, _ := a.blocklist.Get(ctx.Param("key")); !ok {
		ctx.JSON(http.StatusNotFound, Json{"error": ctx.Param("key") + " not found"})
	} else {
		ctx.JSON(http.StatusOK, Json{"success": ok})
	}
}

func (a *API) removeBlock(ctx *Context) {
	ctx.JSON(http.StatusOK, Json{"success": a.blocklist.Remove(ctx.Param("key"))})
}

func (a *API) setBlock(ctx *Context) {
	ctx.JSON(http.StatusOK, Json{"success": a.blocklist.Set(ctx.Param("key"))})
}

func (a *API) metrics(ctx *Context) {
	promhttp.Handler().ServeHTTP(ctx.Writer, ctx.Request)
}

func (a *API) purge(ctx *Context) {
	qtype := strings.ToUpper(ctx.Param("qtype"))
	qname := dns.Fqdn(ctx.Param("qname"))

	bqname := base64.StdEncoding.EncodeToString([]byte(qtype + ":" + qname))

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(bqname), dns.TypeNULL)
	req.Question[0].Qclass = dns.ClassCHAOS

	_, _ = dnsutil.ExchangeInternal(context.Background(), req)

	ctx.JSON(http.StatusOK, Json{"success": true})
}

// Run API server
func (a *API) Run(ctx context.Context) {
	if a.addr == "" {
		return
	}

	if debugpprof {
		profiler := a.router.Group("/debug")
		{
			profiler.GET("/", func(ctx *Context) {
				http.Redirect(ctx.Writer, ctx.Request, profiler.path+"/pprof/", http.StatusMovedPermanently)
			})
			profiler.GET("/pprof/", func(ctx *Context) { pprof.Index(ctx.Writer, ctx.Request) })
			profiler.GET("/pprof/*", func(ctx *Context) { pprof.Index(ctx.Writer, ctx.Request) })
			profiler.GET("/pprof/cmdline", func(ctx *Context) { pprof.Cmdline(ctx.Writer, ctx.Request) })
			profiler.GET("/pprof/profile", func(ctx *Context) { pprof.Profile(ctx.Writer, ctx.Request) })
			profiler.GET("/pprof/symbol", func(ctx *Context) { pprof.Symbol(ctx.Writer, ctx.Request) })
			profiler.GET("/pprof/trace", func(ctx *Context) { pprof.Trace(ctx.Writer, ctx.Request) })
		}
	}

	if a.blocklist != nil {
		block := a.router.Group("/api/v1/block")
		{
			block.GET("/exists/:key", a.existsBlock)
			block.GET("/get/:key", a.getBlock)
			block.GET("/remove/:key", a.removeBlock)
			block.GET("/set/:key", a.setBlock)
		}
	}

	a.router.GET("/api/v1/purge/:qname/:qtype", a.purge)

	a.router.GET("/metrics", a.metrics)

	srv := &http.Server{
		Addr:    a.addr,
		Handler: a.router,
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
