package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/doh"
)

func (h *DNSHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	client, _, _ := net.SplitHostPort(r.RemoteAddr)
	allowed, _ := AccessList.Contains(net.ParseIP(client))
	if !allowed {
		log.Debug("Client denied to make new query", "client", client, "net", "https")
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}

	var f func(http.ResponseWriter, *http.Request)
	if r.Method == http.MethodGet && r.URL.Query().Get("dns") == "" {
		f = h.handleJSON()
	} else {
		f = h.handleWireFormat()
	}

	f(w, r)
}

func (h *DNSHandler) handleWireFormat() func(http.ResponseWriter, *http.Request) {
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

		msg := h.query("http", req)

		packed, err := msg.Pack()
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Server", "SDNS/"+BuildVersion)
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(packed)
	}
}

func (h *DNSHandler) handleJSON() func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		if !strings.HasSuffix(name, ".") {
			buf := bytes.NewBufferString(name)
			buf.WriteString(".")
			name = buf.String()
		}

		qtype := doh.ParseQTYPE(r.URL.Query().Get("type"))
		if qtype == dns.TypeNone {
			http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		req.RecursionDesired = true

		if r.URL.Query().Get("cd") == "true" {
			req.CheckingDisabled = true
		}

		req.Question = []dns.Question{
			dns.Question{
				Name:   name,
				Qtype:  qtype,
				Qclass: dns.ClassINET,
			},
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

		msg := h.query("http", req)

		json, err := json.Marshal(doh.NewMsg(msg))
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Server", "SDNS/"+BuildVersion)

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "application/x-javascript")
		} else {
			w.Header().Set("Content-Type", "application/dns-json")
		}

		w.Write(json)
	}
}
