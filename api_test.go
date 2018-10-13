package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_setBlock(t *testing.T) {

	ginr.GET("/api/v1/block/set/:key", setBlock)

	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/set/test.com", nil)

	assert.Nil(t, err)

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
}

func Test_getBlock(t *testing.T) {

	ginr.GET("/api/v1/block/get/:key", getBlock)

	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/get/test.com", nil)

	assert.Nil(t, err)

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
}

func Test_getBlockExists(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/get/testexists.com", nil)

	assert.Nil(t, err)

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusNotFound)
}

func Test_removeBlock(t *testing.T) {

	ginr.GET("/api/v1/block/remove/:key", removeBlock)

	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/remove/test.com", nil)

	assert.Nil(t, err)

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
}

func Test_existsBlock(t *testing.T) {

	ginr.GET("/api/v1/block/exists/:key", existsBlock)

	request, err := http.NewRequest(http.MethodGet, "/api/v1/block/exists/test.com", nil)

	assert.Nil(t, err)

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
}

func Test_runServer(t *testing.T) {
	err := StartAPIServer(":111111")

	assert.Error(t, err)
}
