package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware"
	"github.com/semihalev/sdns/middleware/blocklist"
	"github.com/semihalev/zlog"
)

func Test_Run(t *testing.T) {
	a := New(&config.Config{})
	a.Run(context.Background())
}

func Test_Authorization(t *testing.T) {
	routes := []struct {
		Method         string
		ReqURL         string
		ExpectedStatus int
	}{
		{"GET", "/api/v1/block/set/test.com", http.StatusUnauthorized},
		{"GET", "/api/v1/block/get/test.com", http.StatusUnauthorized},
		{"GET", "/api/v1/block/exists/test.com", http.StatusUnauthorized},
		{"GET", "/api/v1/block/remove/test.com", http.StatusUnauthorized},
		{"GET", "/api/v1/purge/test.com/A", http.StatusUnauthorized},
		{"GET", "/metrics", http.StatusUnauthorized},
	}

	bearerToken := "secret_token"

	a := New(&config.Config{BearerToken: bearerToken})

	block := a.router.Group("/api/v1/block")
	{
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/get/:key", a.getBlock)
		block.GET("/remove/:key", a.removeBlock)
		block.GET("/set/:key", a.setBlock)
		block.POST("/set/:key", a.setBlock)
	}

	a.router.GET("/api/v1/purge/:qname/:qtype", a.purge)
	a.router.GET("/metrics", a.metrics)

	w := httptest.NewRecorder()
	request, err := http.NewRequest("GET", "/metrics", nil)
	if err != nil {
		t.Fatalf("couldn't create request: %v\n", err)
	}

	a.router.ServeHTTP(w, request)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Authorization not expected status code: %d", w.Code)
	}

	w = httptest.NewRecorder()
	request.Header.Set("Authorization", "sometoken")
	a.router.ServeHTTP(w, request)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Authorization not expected status code: %d", w.Code)
	}

	w = httptest.NewRecorder()
	request.Header.Set("Authorization", fmt.Sprintf("Bearer %s", a.bearerToken))
	a.router.ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("Authorization not expected status code: %d", w.Code)
	}

	for _, r := range routes {
		w := httptest.NewRecorder()
		request, err := http.NewRequest(r.Method, r.ReqURL, nil)

		if err != nil {
			t.Fatalf("couldn't create request: %v\n", err)
		}

		request.Header.Set("Authorization", "Bearer some_token")

		a.router.ServeHTTP(w, request)

		if w.Code != r.ExpectedStatus {
			t.Fatalf("%s uri not expected status code: %d", r.ReqURL, w.Code)
		}
	}
}

func Test_AllAPICalls(t *testing.T) {
	logger := zlog.NewStructured()
	logger.SetWriter(zlog.StdoutTerminal())
	logger.SetLevel(zlog.LevelDebug)
	zlog.SetDefault(logger)
	debugpprof = true

	cfg := new(config.Config)
	cfg.Nullroute = "0.0.0.0"
	cfg.Nullroutev6 = "::0"
	cfg.BlockListDir = filepath.Join(os.TempDir(), "sdns_temp")
	cfg.BearerToken = "secret_token"

	middleware.Register("blocklist", func(cfg *config.Config) middleware.Handler { return blocklist.New(cfg) })
	middleware.Setup(cfg)

	blocklist := middleware.Get("blocklist").(*blocklist.BlockList)
	blocklist.Set("test.com")

	a := New(&config.Config{API: ":11111"})
	ctx, cancel := context.WithCancel(context.Background())
	a.Run(ctx)
	cancel()

	time.Sleep(time.Second)

	a = New(&config.Config{})

	a.router.GET("/", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodGet, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodPost, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodDelete, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodPut, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodPatch, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodConnect, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodTrace, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodOptions, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.Handle(http.MethodHead, "/files", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	a.router.GET("/files/*file", func(ctx *Context) {
		ctx.Writer.WriteHeader(200)
	})

	block := a.router.Group("/api/v1/block")
	{
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/exists/:key", a.existsBlock)
		block.GET("/get/:key", a.getBlock)
		block.GET("/remove/:key", a.removeBlock)
		block.GET("/set/:key", a.setBlock)
		block.POST("/set/:key", a.setBlock)
	}

	a.router.GET("/api/v1/purge/:qname/:qtype", a.purge)
	a.router.GET("/metrics", a.metrics)

	routes := []struct {
		Method         string
		ReqURL         string
		ExpectedStatus int
	}{
		{"GET", "/", http.StatusOK},
		{"GET", "/files", http.StatusOK},
		{"GET", "/files/file.tar.gz", http.StatusOK},
		{"GET", "/api/v1/block/set/test.com", http.StatusOK},
		{"POST", "/api/v1/block/set/test.com", http.StatusOK},
		{"GET", "/api/v1/block/get/test.com", http.StatusOK},
		{"GET", "/api/v1/block/get/test2.com", http.StatusNotFound},
		{"GET", "/api/v1/block/exists/test.com", http.StatusOK},
		{"GET", "/api/v1/block/remove/test.com", http.StatusOK},
		{"GET", "/api/v1/purge/test.com/A", http.StatusOK},
		{"GET", "/metrics", http.StatusOK},
		{"GET", "/notfound", http.StatusNotFound},
	}

	/*w := httptest.NewRecorder()
	a.ServeHTTP(w, nil)
	if w.Code != 500 {
		t.Fatalf("not expected status code: %d", w.Code)
	}*/

	for _, r := range routes {
		w := httptest.NewRecorder()
		request, err := http.NewRequest(r.Method, r.ReqURL, nil)

		if err != nil {
			t.Fatalf("couldn't create request: %v\n", err)
		}

		a.router.ServeHTTP(w, request)

		if w.Code != r.ExpectedStatus {
			t.Fatalf("%s uri not expected status code: %d", r.ReqURL, w.Code)
		}
	}
}
