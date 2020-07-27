package doh

import (
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// HandleWireFormat handle wire format
func HandleWireFormat(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
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
			if r.Header.Get("Content-Type") != "application/dns-message" {
				http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
				return
			}

			buf, err = ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			defer r.Body.Close()
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
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

		w.Header().Set("Server", "SDNS")
		w.Header().Set("Content-Type", "application/dns-message")

		_, _ = w.Write(packed)
	}
}

// HandleJSON handle json format
func HandleJSON(handle func(*dns.Msg) *dns.Msg) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		name = dns.Fqdn(name)

		qtype := ParseQTYPE(r.URL.Query().Get("type"))
		if qtype == dns.TypeNone {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		req.SetQuestion(name, qtype)
		req.AuthenticatedData = true

		if r.URL.Query().Get("cd") == "true" {
			req.CheckingDisabled = true
		}

		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Class:  dns.DefaultMsgSize,
				Rrtype: dns.TypeOPT,
			},
		}

		if r.URL.Query().Get("do") == "true" {
			opt.SetDo()
		}

		if ecs := r.URL.Query().Get("edns_client_subnet"); ecs != "" {
			_, subnet, err := net.ParseCIDR(ecs)
			if err != nil {
				http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
				return
			}

			mask, bits := subnet.Mask.Size()
			var af uint16
			if bits == 32 {
				af = 1
			} else {
				af = 2
			}

			opt.Option = []dns.EDNS0{
				&dns.EDNS0_SUBNET{
					Code:          dns.EDNS0SUBNET,
					Family:        af,
					SourceNetmask: uint8(mask),
					SourceScope:   0,
					Address:       subnet.IP,
				},
			}
		}

		req.Extra = append(req.Extra, opt)

		msg := handle(req)
		if msg == nil {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		json, err := json.Marshal(NewMsg(msg))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Server", "SDNS")

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "application/x-javascript")
		} else {
			w.Header().Set("Content-Type", "application/dns-json")
		}

		_, _ = w.Write(json)
	}
}
