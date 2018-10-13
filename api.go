package main

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/semihalev/log"
	"gopkg.in/gin-contrib/cors.v1"
)

func getBlocks(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"length": blockCache.Length(), "items": blockCache.Backend})
}

func existsBlock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"exists": blockCache.Exists(c.Param("key"))})
}

func lengthBlock(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"length": blockCache.Length()})
}

func getBlock(c *gin.Context) {
	if ok, _ := blockCache.Get(c.Param("key")); !ok {
		c.JSON(http.StatusOK, gin.H{"error": c.Param("key") + " not found"})
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
func StartAPIServer() error {
	gin.SetMode(gin.ReleaseMode)

	r := gin.Default()
	r.Use(cors.Default())

	block := r.Group("/block")
	{
		block.GET("/", getBlocks)
		block.GET("/exists/:key", existsBlock)
		block.GET("/length", lengthBlock)
		block.GET("/get/:key", getBlock)
		block.GET("/remove/:key", removeBlock)
		block.GET("/set/:key", setBlock)
	}

	if err := r.Run(Config.API); err != nil {
		return err
	}

	log.Info("API server listening on", "addr", Config.API)

	return nil
}
