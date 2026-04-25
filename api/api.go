package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/pprof"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/semihalev/sdns/config"
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

// API type.
type API struct {
	addr        string
	bearerToken string
	router      *Router
	blocklist   *blocklist.BlockList
}

var debugpprof bool

func init() {
	_, debugpprof = os.LookupEnv("SDNS_PPROF")
}

// New return new api.
func New(cfg *config.Config) *API {
	var bl *blocklist.BlockList

	b := middleware.Get("blocklist")
	if b != nil {
		bl = b.(*blocklist.BlockList)
	}

	a := &API{
		addr:        cfg.API,
		blocklist:   bl,
		router:      NewRouter(),
		bearerToken: cfg.BearerToken,
	}

	return a
}

func (a *API) checkToken(ctx *Context) bool {
	if a.bearerToken == "" {
		return true
	}

	authHeader := ctx.Request.Header.Get("Authorization")
	if authHeader == "" {
		ctx.JSON(http.StatusUnauthorized, Json{"error": "unauthorized"})
		return false
	}

	tokenSplit := strings.Split(authHeader, " ")
	if len(tokenSplit) != 2 {
		ctx.JSON(http.StatusUnauthorized, Json{"error": "unauthorized"})
		return false
	}

	if tokenSplit[0] == "Bearer" && a.bearerToken == tokenSplit[1] {
		return true
	}

	ctx.JSON(http.StatusUnauthorized, Json{"error": "unauthorized"})
	return false
}

func (a *API) existsBlock(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	ctx.JSON(http.StatusOK, Json{"exists": a.blocklist.Exists(ctx.Param("key"))})
}

func (a *API) getBlock(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	if ok, _ := a.blocklist.Get(ctx.Param("key")); !ok {
		ctx.JSON(http.StatusNotFound, Json{"error": ctx.Param("key") + " not found"})
	} else {
		ctx.JSON(http.StatusOK, Json{"success": ok})
	}
}

func (a *API) removeBlock(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	ctx.JSON(http.StatusOK, Json{"success": a.blocklist.Remove(ctx.Param("key"))})
}

func (a *API) setBlock(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	ctx.JSON(http.StatusOK, Json{"success": a.blocklist.Set(ctx.Param("key"))})
}

// readBatchKeys decodes a {"keys":[...]} JSON body, capped at
// maxBlockBatchBody. Returns the parsed keys or writes the
// appropriate 4xx response and returns nil.
func (a *API) readBatchKeys(ctx *Context) []string {
	ctx.Request.Body = http.MaxBytesReader(ctx.Writer, ctx.Request.Body, maxBlockBatchBody)
	dec := json.NewDecoder(ctx.Request.Body)
	dec.DisallowUnknownFields()

	var req blockBatchRequest
	if err := dec.Decode(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, Json{"error": "invalid request body: " + err.Error()})
		return nil
	}
	if len(req.Keys) == 0 {
		ctx.JSON(http.StatusBadRequest, Json{"error": "keys is required and must be non-empty"})
		return nil
	}
	return req.Keys
}

func (a *API) setBlockBatch(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}
	keys := a.readBatchKeys(ctx)
	if keys == nil {
		return
	}
	added := a.blocklist.SetBatch(keys)
	ctx.JSON(http.StatusOK, Json{
		"requested": len(keys),
		"added":     added,
		"skipped":   len(keys) - added,
	})
}

func (a *API) removeBlockBatch(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}
	keys := a.readBatchKeys(ctx)
	if keys == nil {
		return
	}
	removed := a.blocklist.RemoveBatch(keys)
	ctx.JSON(http.StatusOK, Json{
		"requested": len(keys),
		"removed":   removed,
		"missing":   len(keys) - removed,
	})
}

func (a *API) metrics(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	promhttp.Handler().ServeHTTP(ctx.Writer, ctx.Request)
}

func (a *API) purge(ctx *Context) {
	if !a.checkToken(ctx) {
		return
	}

	qtypeName := strings.ToUpper(ctx.Param("qtype"))
	qtype, ok := dns.StringToType[qtypeName]
	if !ok {
		ctx.JSON(http.StatusBadRequest, Json{"error": "unknown qtype: " + qtypeName})
		return
	}
	q := dns.Question{
		Name:   dns.Fqdn(ctx.Param("qname")),
		Qtype:  qtype,
		Qclass: dns.ClassINET,
	}

	// Invalidate every purger the pipeline exposes — today that's
	// the cache middleware (positive + negative entries) and the
	// resolver handler (NS cache, TypeNS only). No synthesised
	// CHAOS-NULL query, no base64 encoding; just a direct call.
	for _, p := range middleware.GlobalPipeline().Purgers() {
		p.Purge(q)
	}

	ctx.JSON(http.StatusOK, Json{"success": true})
}

// (*API).Run run API server.
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
			block.POST("/set/batch", a.setBlockBatch)
			block.POST("/remove/batch", a.removeBlockBatch)
		}
	}

	a.router.GET("/api/v1/purge/:qname/:qtype", a.purge)

	a.router.GET("/metrics", a.metrics)

	srv := &http.Server{
		Addr:              a.addr,
		Handler:           a.router,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			zlog.Error("Start API server failed", "error", err.Error())
		}
	}()

	zlog.Info("API server listening...", "addr", a.addr)
	if a.bearerToken != "" {
		// Never log the token itself — anyone who can read process
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
