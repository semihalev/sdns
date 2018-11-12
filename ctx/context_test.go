package ctx

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/miekg/dns"
	"github.com/semihalev/sdns/mock"
	"github.com/stretchr/testify/assert"
)

type dummy struct{}

func (d *dummy) ServeDNS(dc *Context)  { dc.NextDNS() }
func (d *dummy) ServeHTTP(dc *Context) { dc.NextHTTP() }
func (d *dummy) Name() string          { return "dummy" }

func Test_Context(t *testing.T) {
	w := mock.NewWriter("udp", "127.0.0.1")
	dc := New([]Handler{&dummy{}})
	req := new(dns.Msg)
	req.SetQuestion("test.com.", dns.TypeA)

	dc.ResetDNS(w, req)

	dc.NextDNS()

	req.Rcode = dns.RcodeSuccess
	dc.DNSWriter.WriteMsg(req)

	data, err := req.Pack()
	assert.NoError(t, err)

	assert.Equal(t, true, dc.DNSWriter.Written())
	assert.Equal(t, dns.RcodeSuccess, dc.DNSWriter.Rcode())

	_, err = dc.DNSWriter.Write(data)
	assert.Equal(t, errAlreadyWritten, err)

	dc.ResetDNS(mock.NewWriter("udp", "127.0.0.1"), req)
	size, err := dc.DNSWriter.Write(data)
	assert.NoError(t, err)
	assert.Equal(t, len(data), size)
	assert.NotNil(t, dc.DNSWriter.Msg())

	err = dc.DNSWriter.WriteMsg(req)
	assert.Equal(t, errAlreadyWritten, err)

	dc.ResetDNS(mock.NewWriter("udp", "127.0.0.1"), req)
	_, err = dc.DNSWriter.Write([]byte{})
	assert.Error(t, err)

	dc.Abort()
	assert.Equal(t, abortIndex, dc.index)

	request, err := http.NewRequest("GET", "/dns-query?name=test.com", nil)
	assert.NoError(t, err)
	request.RemoteAddr = "127.0.0.1:0"

	hw := httptest.NewRecorder()
	dc.ResetHTTP(hw, request)

	dc.NextHTTP()
}
