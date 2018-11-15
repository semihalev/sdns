package api

import (
	"net/http"
	"os"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/middleware/blocklist"
	"gopkg.in/gin-contrib/cors.v1"
)

// API type
type API struct {
	host      string
	blocklist *blocklist.BlockList
}

var debugpprof bool

func init() {
	gin.SetMode(gin.ReleaseMode)

	_, debugpprof = os.LookupEnv("SDNS_PPROF")
}

// New return new api
func New(host string, blocklist *blocklist.BlockList) *API {
	return &API{
		host:      host,
		blocklist: blocklist,
	}
}

func (a *API) existsBlock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"exists": a.blocklist.Exists(c.Param("key"))})
}

func (a *API) getBlock(c *gin.Context) {
	if ok, _ := a.blocklist.Get(dns.Fqdn(c.Param("key"))); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": c.Param("key") + " not found"})
	} else {
		c.JSON(http.StatusOK, gin.H{"success": ok})
	}
}

func (a *API) removeBlock(c *gin.Context) {
	a.blocklist.Remove(dns.Fqdn(c.Param("key")))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *API) setBlock(c *gin.Context) {
	a.blocklist.Set(dns.Fqdn(c.Param("key")))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func (a *API) metrics(c *gin.Context) {
	promhttp.Handler().ServeHTTP(c.Writer, c.Request)
}

// Run API server
func (a *API) Run() {
	if a.host == "" {
		return
	}

	r := gin.Default()
	r.Use(cors.Default())

	if debugpprof {
		pprof.Register(r)
	}

	block := r.Group("/api/v1/block")
	{
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/get/:key", a.getBlock)
		block.GET("/remove/:key", a.removeBlock)
		block.GET("/set/:key", a.setBlock)
	}

	r.GET("/metrics", a.metrics)

	go func() {
		if err := r.Run(a.host); err != nil {
			log.Error("Start API server failed", "error", err.Error())
		}
	}()

	log.Info("API server listening...", "addr", a.host)
}
