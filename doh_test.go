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
	Config.Maxdepth = 30
	Config.Interval = 200

	h := NewHandler()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&type=a&do=true&cd=true&edns_client_subnet=127.0.0.1/32", nil)
	assert.NoError(t, err)

	h.ServeHTTP(w, request)

	assert.Equal(t, w.Code, http.StatusOK)

	data, err := ioutil.ReadAll(w.Body)
	assert.NoError(t, err)

	var dm doh.Msg
	err = json.Unmarshal(data, &dm)
	assert.NoError(t, err)

	assert.Equal(t, len(dm.Answer) > 0, true)
}

func Test_dohWIREGET(t *testing.T) {
	Config.Maxdepth = 30
	Config.Interval = 200

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

func Test_dohWIREPOST(t *testing.T) {
	Config.Maxdepth = 30
	Config.Interval = 200

	h := NewHandler()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)
	req.RecursionDesired = true

	data, err := req.Pack()
	assert.NoError(t, err)

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader(data))
	assert.NoError(t, err)

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
