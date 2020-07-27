package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"os"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
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
	host      string
	blocklist *blocklist.BlockList
}

var debugpprof bool

func init() {
	gin.SetMode(gin.ReleaseMode)

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
		host:      cfg.API,
		blocklist: bl,
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

func (a *API) purge(c *gin.Context) {
	qtype := strings.ToUpper(c.Param("qtype"))
	qname := dns.Fqdn(c.Param("qname"))

	bqname := base64.StdEncoding.EncodeToString([]byte(qtype + ":" + qname))

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(bqname), dns.TypeNULL)
	req.Question[0].Qclass = dns.ClassCHAOS

	_, _ = dnsutil.ExchangeInternal(context.Background(), req)

	c.JSON(http.StatusOK, gin.H{"success": true})
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

	if a.blocklist != nil {
		block := r.Group("/api/v1/block")
		{
			block.GET("/exists/:key", a.existsBlock)
			block.GET("/get/:key", a.getBlock)
			block.GET("/remove/:key", a.removeBlock)
			block.GET("/set/:key", a.setBlock)
		}
	}

	r.GET("/api/v1/purge/:qname/:qtype", a.purge)
	r.GET("/metrics", a.metrics)

	go func() {
		if err := r.Run(a.host); err != nil {
			log.Error("Start API server failed", "error", err.Error())
		}
	}()

	log.Info("API server listening...", "addr", a.host)
}
