package main

import (
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

const (
	testNameserver = "127.0.0.1:53"
	testDomain     = "www.google.com"
)

var (
	ginr *gin.Engine
)

func TestMain(m *testing.M) {

	gin.SetMode(gin.TestMode)
	ginr = gin.Default()

	block := ginr.Group("/api/v1/block")
	{
		block.GET("/exists/:key", existsBlock)
		block.GET("/get/:key", getBlock)
		block.GET("/remove/:key", removeBlock)
		block.GET("/set/:key", setBlock)
	}

	m.Run()
}

func BenchmarkResolver(b *testing.B) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)

	c := new(dns.Client)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Exchange(m, testNameserver)
	}
}
