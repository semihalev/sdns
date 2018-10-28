package pprof

import (
	"net/http"
	"net/http/pprof"

	"github.com/gin-gonic/gin"
)

// Options provides potential route registration configuration options
type Options struct {
	// RoutePrefix is an optional path prefix. If left unspecified, `/debug/pprof`
	// is used as the default path prefix.
	RoutePrefix string
}

// Register the standard HandlerFuncs from the net/http/pprof package with
// the provided gin.Engine. opts is a optional. If a `nil` value is passed,
// the default path prefix is used.
func Register(r *gin.Engine, opts *Options) {
	prefix := routePrefix(opts)
	r.GET(prefix+"/block", pprofHandler(pprof.Index))
	r.GET(prefix+"/heap", pprofHandler(pprof.Index))
	r.GET(prefix+"/profile", pprofHandler(pprof.Profile))
	r.POST(prefix+"/symbol", pprofHandler(pprof.Symbol))
	r.GET(prefix+"/symbol", pprofHandler(pprof.Symbol))
	r.GET(prefix+"/trace", pprofHandler(pprof.Trace))
}

func pprofHandler(h http.HandlerFunc) gin.HandlerFunc {
	handler := http.HandlerFunc(h)
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

func routePrefix(opts *Options) string {
	if opts == nil {
		return "/debug/pprof"
	}
	return opts.RoutePrefix
}
