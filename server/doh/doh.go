package doh

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/semihalev/sdns/internal/metric"
)

// httpErrors counts DoH responses sent with a 4xx or 5xx status.
// Labelled by status code (closed set: 400/405/415/500) so operators
// can distinguish bad-request floods from server-side decode
// failures. The 200-path is not counted here, that's what
// dns_queries_total already measures.
var (
	httpErrors = metric.NewCounterVec(nil, prometheus.CounterOpts{
		Name: "dns_doh_http_errors_total",
		Help: "DoH responses returned with a 4xx or 5xx HTTP status, by code",
	}, []string{"code"})

	httpErr400 = httpErrors.Register("400")
	httpErr405 = httpErrors.Register("405")
	httpErr415 = httpErrors.Register("415")
	httpErr500 = httpErrors.Register("500")
)

// writeHTTPError replaces http.Error + manual metric increments so
// every error response goes through one bookkeeping site. Unknown
// status codes fall through to the cold WithLabelValues path so the
// metric stays correct without forcing every caller to update this
// switch.
func writeHTTPError(w http.ResponseWriter, code int) {
	switch code {
	case http.StatusBadRequest:
		httpErr400.Inc()
	case http.StatusMethodNotAllowed:
		httpErr405.Inc()
	case http.StatusUnsupportedMediaType:
		httpErr415.Inc()
	case http.StatusInternalServerError:
		httpErr500.Inc()
	default:
		httpErrors.WithLabelValues(strconv.Itoa(code)).Inc()
	}
	http.Error(w, http.StatusText(code), code)
}

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
				writeHTTPError(w, http.StatusBadRequest)
				return
			}
		case http.MethodPost:
			if r.Header.Get("Content-Type") != contentTypeDNS {
				writeHTTPError(w, http.StatusUnsupportedMediaType)
				return
			}

			// Limit request body size to prevent DoS
			limitedReader := io.LimitReader(r.Body, maxMsgSize)
			defer r.Body.Close()

			buf, err = io.ReadAll(limitedReader)
			if err != nil {
				writeHTTPError(w, http.StatusInternalServerError)
				return
			}
		default:
			writeHTTPError(w, http.StatusMethodNotAllowed)
			return
		}

		if len(buf) < minMsgHeaderSize {
			writeHTTPError(w, http.StatusBadRequest)
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(buf); err != nil {
			writeHTTPError(w, http.StatusBadRequest)
			return
		}

		msg := handle(req)
		if msg == nil {
			if r.Context().Err() != nil {
				return
			}
			writeHTTPError(w, http.StatusBadRequest)
			return
		}

		packed, err := msg.Pack()
		if err != nil {
			writeHTTPError(w, http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeDNS)
		w.Header().Set("Cache-Control", cacheControl(msg))

		_, _ = w.Write(packed)
	}
}

// noStore is the Cache-Control of a response an HTTP cache must not keep.
const noStore = "no-cache, no-store"

// cacheControl is the HTTP freshness of msg (RFC 8484 §5.1): no longer than
// the smallest TTL it carries, and for a denial no longer than its SOA says
// a denial lives (RFC 2308 §5). A failure, or a reply with nothing to take
// a lifetime from, is not kept.
func cacheControl(msg *dns.Msg) string {
	if msg.Rcode != dns.RcodeSuccess && msg.Rcode != dns.RcodeNameError {
		return noStore
	}
	ttl, found := uint32(0), false
	lower := func(v uint32) {
		if !found || v < ttl {
			ttl, found = v, true
		}
	}
	for _, rr := range msg.Answer {
		lower(rr.Header().Ttl)
	}
	for _, rr := range msg.Ns {
		lower(rr.Header().Ttl)
		if soa, ok := rr.(*dns.SOA); ok && len(msg.Answer) == 0 {
			lower(soa.Minttl)
		}
	}
	if !found {
		return noStore
	}
	// private: the answer can be this client's own, shaped by its source
	// address through ECS or carrying a server cookie derived from it, and
	// a shared HTTP cache keyed by URL would hand it to another client.
	return "private, max-age=" + strconv.FormatUint(uint64(ttl), 10)
}

// HandleJSON handle json format.
func HandleJSON(handle func(*dns.Msg) *dns.Msg) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Only allow GET for JSON API
		if r.Method != http.MethodGet {
			writeHTTPError(w, http.StatusMethodNotAllowed)
			return
		}

		query := r.URL.Query()
		name := query.Get("name")
		if name == "" {
			writeHTTPError(w, http.StatusBadRequest)
			return
		}
		name = dns.Fqdn(name)

		qtype := ParseQTYPE(query.Get("type"))
		if qtype == dns.TypeNone {
			writeHTTPError(w, http.StatusBadRequest)
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
			if r.Context().Err() != nil {
				return
			}
			writeHTTPError(w, http.StatusBadRequest)
			return
		}

		jsonData, err := json.Marshal(NewMsg(msg))
		if err != nil {
			writeHTTPError(w, http.StatusInternalServerError)
			return
		}

		if strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", contentTypeJS)
		} else {
			w.Header().Set("Content-Type", contentTypeJSON)
		}
		w.Header().Set("Cache-Control", cacheControl(msg))

		_, _ = w.Write(jsonData)
	}
}
