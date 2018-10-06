package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

var (
	ginr *gin.Engine
)

func TestMain(m *testing.M) {

	blockCache.Set("cf", true)
	gin.SetMode(gin.TestMode)
	ginr = gin.Default()

	m.Run()
}

func Test_getBlocks(t *testing.T) {

	ginr.GET("/block", getBlocks)

	request, err := http.NewRequest(http.MethodGet, "/block", nil)

	if err != nil {
		t.Fatalf("Couldn't create request: %v\n", err)
	}

	w := httptest.NewRecorder()

	ginr.ServeHTTP(w, request)

	if w.Code != http.StatusOK {
		t.Fatalf("Its not okey!")
	}

	js := struct {
		Items struct {
			Key bool `json:"cf"`
		} `json:"items"`
		Length int `json:"length"`
	}{}

	_ = json.Unmarshal(w.Body.Bytes(), &js)

	if js.Length < 1 {
		t.Error("invalid lenght")
	}

	log.Println("Key:", js.Items.Key)
	log.Println("Lenght:", js.Length)
}
