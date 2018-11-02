package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/doh"
	"github.com/stretchr/testify/assert"
)

func Test_dohJSON(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&type=a&do=true&cd=true&edns_client_subnet=127.0.0.1/32", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err := ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	var dm doh.Msg
	err = json.Unmarshal(data, &dm)
	assert.NoError(t, err)

	assert.Equal(t, len(dm.Answer) > 0, true)
}

func Test_dohJSONerror(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohJSONuknownType(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&type=unknown", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohJSONsubnet(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&edns_client_subnet=127.0.0.1", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohJSONaccepthtml(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	request.Header.Add("Accept", "text/html")
	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)
	assert.Equal(t, w.Header().Get("Content-Type"), "application/x-javascript")
}

func Test_dohWireGET(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true

	data, err := req.Pack()
	assert.NoError(t, err)

	dq := base64.RawURLEncoding.EncodeToString(data)

	request, err := http.NewRequest("GET", fmt.Sprintf("/dns-query?dns=%s", dq), nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	assert.NoError(t, err)

	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)

	assert.Equal(t, len(msg.Answer) > 0, true)
}

func Test_dohWireGETerror(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohWireGETbadquery(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=Df4", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusBadRequest)
}

func Test_dohWireHEAD(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("HEAD", "/dns-query?dns=", nil)
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusMethodNotAllowed)
}

func Test_dohWirePOST(t *testing.T) {
	t.Parallel()

	h := NewHandler()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true

	data, err := req.Pack()
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader(data))
	assert.NoError(t, err)

	request.RemoteAddr = "127.0.0.1:0"
	request.Header.Add("Content-Type", "application/dns-message")

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err = ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	assert.NoError(t, err)

	assert.Equal(t, msg.Rcode, dns.RcodeSuccess)

	assert.Equal(t, len(msg.Answer) > 0, true)
}
