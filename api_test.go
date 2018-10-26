package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_AllAPICalls(t *testing.T) {

	BlockList.Set("test.com")

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
