package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
)

func Test_Run(t *testing.T) {
	a := New(&config.Config{})
	a.Run()
}

func Test_AllAPICalls(t *testing.T) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))
	debugpprof = true

	gin.SetMode(gin.TestMode)
	ginr := gin.New()

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"

	middleware.Setup(cfg)

	blocklist := middleware.Get("blocklist").(*blocklist.BlockList)
	blocklist.Set("test.com")

	a := New(&config.Config{API: ":11111"})
	a.Run()

	time.Sleep(time.Second)

	a.Run()

	block := ginr.Group("/api/v1/block")
	{
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/get/:key", a.getBlock)
		block.GET("/remove/:key", a.removeBlock)
		block.GET("/set/:key", a.setBlock)
	}

	ginr.GET("/api/v1/purge/test.com/A", a.purge)
	ginr.GET("/metrics", a.metrics)

	routes := []struct {
		Method         string
		ReqURL         string
		ExpectedStatus int
	}{
		{"GET", "/api/v1/block/set/test.com", http.StatusOK},
		{"GET", "/api/v1/block/get/test.com", http.StatusOK},
		{"GET", "/api/v1/block/get/test2.com", http.StatusOK},
		{"GET", "/api/v1/block/exists/test.com", http.StatusOK},
		{"GET", "/api/v1/block/remove/test.com", http.StatusOK},
		{"GET", "/api/v1/purge/test.com/A", http.StatusOK},
		{"GET", "/metrics", http.StatusOK},
	}

	w := httptest.NewRecorder()

	for _, r := range routes {
		request, err := http.NewRequest(r.Method, r.ReqURL, nil)

		if err != nil {
			t.Fatalf("couldn't create request: %v\n", err)
		}

		ginr.ServeHTTP(w, request)

		if w.Code != r.ExpectedStatus {
			t.Fatalf("not expected status code: %d", w.Code)
		}
	}
}
