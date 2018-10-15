package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_AllAPICalls(t *testing.T) {

	blockCache.Set("test.com", true)

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

func Test_runServer(t *testing.T) {
	err := runAPIServer(":111111")
	assert.Error(t, err)
}

// func Test_getBlockExists(t *testing.T) {
// 	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/get/testexists.com", nil)

// 	assert.NoError(t, err)

// 	w := httptest.NewRecorder()

// 	ginr.ServeHTTP(w, request)

// 	assert.Equal(t, w.Code, http.StatusNotFound)
// }

// func Test_removeBlock(t *testing.T) {

// 	ginr.GET("/api/v1/block/remove/:key", removeBlock)

// 	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/remove/test.com", nil)

// 	assert.NoError(t, err)

// 	w := httptest.NewRecorder()

// 	ginr.ServeHTTP(w, request)

// 	assert.Equal(t, w.Code, http.StatusOK)
// }

// func Test_existsBlock(t *testing.T) {

// 	ginr.GET("/api/v1/block/exists/:key", existsBlock)

// 	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/exists/test.com", nil)

// 	assert.NoError(t, err)

// 	w := httptest.NewRecorder()

// 	ginr.ServeHTTP(w, request)

// 	assert.Equal(t, w.Code, http.StatusOK)
// }
// func Test_runServer(t *testing.T) {
// 	err := StartAPIServer(":111111")
// 	assert.Error(t, err)
// }
