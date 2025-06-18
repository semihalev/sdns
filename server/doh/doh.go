package doh

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

const (
	minMsgHeaderSize = 12
	maxMsgSize       = 65535 // Maximum DNS message size
	contentTypeDNS   = "application/dns-message"
	contentTypeJSON  = "application/dns-json"
	contentTypeJS    = "application/x-javascript"
)

// HandleWireFormat handle wire format.
func HandleWireFormat(handle func(*dns.Msg) *dns.Msg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			buf []byte
			err error
		)

		switch r.Method {
		case http.MethodGet:
			buf, err = base64.RawURLEncoding.DecodeString(r.URL.Query().Get("dns"))
			if len(buf) == 0 || err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if r.Header.Get("Content-Type") != contentTypeDNS {
				http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
				return
			}

			// Limit request body size to prevent DoS
			limitedReader := io.LimitReader(r.Body, maxMsgSize)
			defer r.Body.Close()

			buf, err = io.ReadAll(limitedReader)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		if len(buf) < minMsgHeaderSize {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		msg := handle(req)
		if msg == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		packed, err := msg.Pack()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeDNS)
		w.Header().Set("Cache-Control", "no-cache, no-store")

		_, _ = w.Write(packed)
	}
}

// HandleJSON handle json format.
func HandleJSON(handle func(*dns.Msg) *dns.Msg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET for JSON API
		if r.Method != http.MethodGet {
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}

		query := r.URL.Query()
		name := query.Get("name")
		if name == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		name = dns.Fqdn(name)

		qtype := ParseQTYPE(query.Get("type"))
		if qtype == dns.TypeNone {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		req.AuthenticatedData = true

		// Parse boolean parameters
		if query.Get("cd") == "true" {
			req.CheckingDisabled = true
		}

		// Use SetEdns0 helper for cleaner code
		req.SetEdns0(dns.DefaultMsgSize, query.Get("do") == "true")

		msg := handle(req)
		if msg == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		jsonData, err := json.Marshal(NewMsg(msg))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", contentTypeJS)
		} else {
			w.Header().Set("Content-Type", contentTypeJSON)
		}
		w.Header().Set("Cache-Control", "no-cache, no-store")

		_, _ = w.Write(jsonData)
	}
}
