package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

var (
	ginr *gin.Engine
)

func TestMain(m *testing.M) {

	blockCache.Set("test.com", true)
	gin.SetMode(gin.TestMode)
	ginr = gin.Default()

	m.Run()
}

func Test_getBlocks(t *testing.T) {

	ginr.GET("/api/v1/block/:key", getBlock)

	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/test.com", nil)

	if err != nil {
		t.Fatalf("Couldn't create request: %v\n", err)
	}

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("Its not okey!")
	}
}
