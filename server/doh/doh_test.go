package doh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/miekg/dns"
)

func handleTest(w http.ResponseWriter, r *http.Request) {
	// Answer locally. These tests are about the HTTP framing DoH puts
	// around a DNS message — status codes, media types, JSON shape — and
	// none of that needs a real resolver. Every request used to go to
	// 8.8.8.8, so the whole file failed on a machine without internet, and
	// what it verified depended on Google's answer for www.google.com.
	handle := func(req *dns.Msg) *dns.Msg {
		msg := new(dns.Msg)
		msg.SetReply(req)
		msg.RecursionAvailable = true
		if len(req.Question) == 1 {
			rr, err := dns.NewRR(req.Question[0].Name + " 300 IN A 192.0.2.1")
			if err == nil {
				msg.Answer = append(msg.Answer, rr)
			}
		}
		return msg
	}

	var handleFn func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		handleFn = HandleJSON(handle)
	} else {
		handleFn = HandleWireFormat(handle)
	}

	handleFn(w, r)
}
func Test_dohJSON(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com&type=a&do=true&cd=true", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusOK) {
		t.Errorf("http.StatusOK = %v, want %v", http.StatusOK, w.Code)
	}

	data, err := io.ReadAll(w.Body)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	var dm Msg
	err = json.Unmarshal(data, &dm)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(len(dm.Answer) > 0, true) {
		t.Errorf("true = %v, want %v", true, len(dm.Answer) > 0)
	}
}

func Test_dohJSONerror(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusBadRequest) {
		t.Errorf("http.StatusBadRequest = %v, want %v", http.StatusBadRequest, w.Code)
	}
}

func Test_dohJSONaccepthtml(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=www.google.com", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	request.Header.Add("Accept", "text/html")
	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusOK) {
		t.Errorf("http.StatusOK = %v, want %v", http.StatusOK, w.Code)
	}
	if !reflect.DeepEqual(w.Header().Get("Content-Type"), "application/x-javascript") {
		t.Errorf("'application/x-javascript' = %v, want %v", "application/x-javascript", w.Header().Get("Content-Type"))
	}
}

func Test_dohWireGET(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)

	data, err := req.Pack()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	dq := base64.RawURLEncoding.EncodeToString(data)

	request, err := http.NewRequest("GET", fmt.Sprintf("/dns-query?dns=%s", dq), nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusOK) {
		t.Errorf("http.StatusOK = %v, want %v", http.StatusOK, w.Code)
	}

	data, err = io.ReadAll(w.Body)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(msg.Rcode, dns.RcodeSuccess) {
		t.Errorf("dns.RcodeSuccess = %v, want %v", dns.RcodeSuccess, msg.Rcode)
	}

	if !reflect.DeepEqual(len(msg.Answer) > 0, true) {
		t.Errorf("true = %v, want %v", true, len(msg.Answer) > 0)
	}
}

func Test_dohWireGETerror(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusBadRequest) {
		t.Errorf("http.StatusBadRequest = %v, want %v", http.StatusBadRequest, w.Code)
	}
}

func Test_dohWireGETbadquery(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?dns=Df4", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusBadRequest) {
		t.Errorf("http.StatusBadRequest = %v, want %v", http.StatusBadRequest, w.Code)
	}
}

func Test_dohWireHEAD(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("HEAD", "/dns-query?dns=", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusMethodNotAllowed) {
		t.Errorf("http.StatusMethodNotAllowed = %v, want %v", http.StatusMethodNotAllowed, w.Code)
	}
}

func Test_dohWirePOST(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("www.google.com.", dns.TypeA)

	data, err := req.Pack()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader(data))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"
	request.Header.Add("Content-Type", "application/dns-message")

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusOK) {
		t.Errorf("http.StatusOK = %v, want %v", http.StatusOK, w.Code)
	}

	data, err = io.ReadAll(w.Body)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	msg := new(dns.Msg)
	err = msg.Unpack(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if !reflect.DeepEqual(msg.Rcode, dns.RcodeSuccess) {
		t.Errorf("dns.RcodeSuccess = %v, want %v", dns.RcodeSuccess, msg.Rcode)
	}

	if !reflect.DeepEqual(len(msg.Answer) > 0, true) {
		t.Errorf("true = %v, want %v", true, len(msg.Answer) > 0)
	}
}

func Test_dohWirePOSTError(t *testing.T) {
	t.Parallel()

	w := httptest.NewRecorder()

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader([]byte{}))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request.RemoteAddr = "127.0.0.1:0"
	request.Header.Add("Content-Type", "text/html")

	handleTest(w, request)

	if !reflect.DeepEqual(w.Code, http.StatusUnsupportedMediaType) {
		t.Errorf("http.StatusUnsupportedMediaType = %v, want %v", http.StatusUnsupportedMediaType, w.Code)
	}
}

func Test_dohWireHandlerReturnsNil(t *testing.T) {
	t.Parallel()

	nilHandle := func(req *dns.Msg) *dns.Msg {
		return nil
	}

	w := httptest.NewRecorder()

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	data, err := req.Pack()
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	request, err := http.NewRequest("POST", "/dns-query", bytes.NewReader(data))
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	request.Header.Add("Content-Type", "application/dns-message")

	HandleWireFormat(nilHandle)(w, request)

	if !reflect.DeepEqual(http.StatusBadRequest, w.Code) {
		t.Errorf("w.Code = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func Test_dohJSONHandlerReturnsNil(t *testing.T) {
	t.Parallel()

	nilHandle := func(req *dns.Msg) *dns.Msg {
		return nil
	}

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=example.com&type=A", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	HandleJSON(nilHandle)(w, request)

	if !reflect.DeepEqual(http.StatusBadRequest, w.Code) {
		t.Errorf("w.Code = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func Test_dohJSONInvalidType(t *testing.T) {
	t.Parallel()

	handle := func(req *dns.Msg) *dns.Msg {
		return req
	}

	w := httptest.NewRecorder()

	request, err := http.NewRequest("GET", "/dns-query?name=example.com&type=INVALID", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	HandleJSON(handle)(w, request)

	if !reflect.DeepEqual(http.StatusBadRequest, w.Code) {
		t.Errorf("w.Code = %v, want %v", w.Code, http.StatusBadRequest)
	}
}

func Test_dohJSONMethodNotAllowed(t *testing.T) {
	t.Parallel()

	handle := func(req *dns.Msg) *dns.Msg {
		return req
	}

	w := httptest.NewRecorder()

	request, err := http.NewRequest("POST", "/dns-query?name=example.com&type=A", nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	HandleJSON(handle)(w, request)

	if !reflect.DeepEqual(http.StatusMethodNotAllowed, w.Code) {
		t.Errorf("w.Code = %v, want %v", w.Code, http.StatusMethodNotAllowed)
	}
}
