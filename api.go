package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/semihalev/log"
	"gopkg.in/gin-contrib/cors.v1"
)

func existsBlock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"exists": blockCache.Exists(c.Param("key"))})
}

func getBlock(c *gin.Context) {
	if ok, _ := blockCache.Get(c.Param("key")); !ok {
		c.JSON(http.StatusNotFound, gin.H{"error": c.Param("key") + " not found"})
	} else {
		c.JSON(http.StatusOK, gin.H{"success": ok})
	}
}

func removeBlock(c *gin.Context) {
	blockCache.Remove(c.Param("key"))
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func setBlock(c *gin.Context) {
	blockCache.Set(c.Param("key"), true)
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// StartAPIServer launches the API server
func StartAPIServer(addr string) error {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	r.Use(cors.Default())

	block := r.Group("/api/v1/block")
	{
		block.GET("/exists/:key", existsBlock)
		block.GET("/get/:key", getBlock)
		block.GET("/remove/:key", removeBlock)
		block.GET("/set/:key", setBlock)
	}

	if err := r.Run(addr); err != nil {
		return err
	}

	log.Info("API server listening on", "addr", addr)

	return nil
}
