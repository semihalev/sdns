package main

import (
	"net/http"
	"os"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"gopkg.in/gin-contrib/cors.v1"
)

// API type
type API struct {
	host string
}

var debugpprof bool

func init() {
	_, debugpprof = os.LookupEnv("SDNS_PPROF")
}

func existsBlock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"exists": BlockList.Exists(c.Param("key"))})
}

func getBlock(c *gin.Context) {
	if ok, _ := BlockList.Get(dns.Fqdn(c.Param("key"))); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": c.Param("key") + " not found"})
	} else {
		c.JSON(http.StatusOK, gin.H{"success": ok})
	}
}

func removeBlock(c *gin.Context) {
	BlockList.Remove(dns.Fqdn(c.Param("key")))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func setBlock(c *gin.Context) {
	BlockList.Set(dns.Fqdn(c.Param("key")))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// Run API server
func (a *API) Run() {
	if a.host == "" {
		return
	}

	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	r.Use(cors.Default())

	if debugpprof {
		pprof.Register(r)
	}

	block := r.Group("/api/v1/block")
	{
		block.GET("/exists/:key", existsBlock)
		block.GET("/get/:key", getBlock)
		block.GET("/remove/:key", removeBlock)
		block.GET("/set/:key", setBlock)
	}

	go func() {
		if err := r.Run(a.host); err != nil {
			log.Crit("Start API server failed", "error", err.Error())
		}
	}()

	log.Info("API server listening...", "addr", a.host)
}
