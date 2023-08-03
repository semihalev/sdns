package resolver_test

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/semihalev/log"
	"github.com/semihalev/sdns/authcache"
	"github.com/semihalev/sdns/config"
	"github.com/semihalev/sdns/middleware/resolver"
	"github.com/stretchr/testify/assert"
)

var (
	privateKey = "MIICXAIBAAKBgQCWIKiOFx/LqVppaUSfW2a9hEnfUS+Qb752/fL3odiGQxCrxcmcEXvn+APSN3ipRetdLdHeB7FSZQ4eIhBtgKjBuFlqQj8pnZOWhV16w80HFjYg/ea9nhG8IziTzK/lsSIk2cDTe1k9kD5WUaLRijLJEEy7gLkOOFmt3Ho675dw2QIDAQABAoGANYEsMX/iUBZqZ5kh4N2Vb0O/hDyOBB8fNY9qUYE4BxnNzjpukRXWICVPT1N/yGxn5syWuFfrhZ8IegrP6gbpnZ1ViYRONOkrfoGOm/U71IL8mlr/NCrxAd/ifB4Db1HOEvlewwQ3G8+HE7HBAjYpup+w4Yw/Du2Cw6dtlJ9MmWUCQQDDHj0MCxWus38EHBwueVjmKq/gE1oZpuLCGmjVZIXlA7yw4IlQU27Y+XlEdVJIMRIUQ1K7Zdw/KFU+aKfBmYy3AkEAxPijYGdWPSZDZn/9tPMfdBtipz1wXHREHLBNOPOcgP4TjVoqBY8Yl6ZUwwjTA8C2JZ1ZU4oSUyLuecbH/N1+7wJAVb2w99zbH1UTSLwNikKa1TIG7UGzwzf5x3ARh0xQJk4ZGeThkmHHgSNHrdScXsrpdewLq/vb6AkSRIV6ynFuSwJAHLk5cfR/0fkDeS4O/FU77/2SXFsMSJ8304suJ7D20KS8iy9r01Wzu2GpGKvvwatXpJKWlSUcWP1OE3oWbdyLBwJBAMCcuKf9EIw9Wgkt9KKhJXKpSqUr1xN+3WZf4bmQl4nT1mITMPcmnQla/JYepnspYrt06L16Ed8vf4u8AbEW68I="
)

type dummyHandler struct {
	DNSKEY []dns.RR
}

func (d *dummyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.Question = r.Question
	resp.Authoritative = true
	resp.SetRcode(r, dns.RcodeSuccess)

	if r.Question[0].Qtype == dns.TypeDNSKEY {
		resp.Answer = append(resp.Answer, d.DNSKEY...)
	}

	_ = w.WriteMsg(resp)
}

func makeRootKeysConfig() *config.Config {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	cfg := new(config.Config)
	cfg.RootServers = []string{"127.0.0.1:44302"}
	cfg.RootKeys = []string{
		".	86400	IN	DNSKEY	257 3 8 AwEAAZYgqI4XH8upWmlpRJ9bZr2ESd9RL5Bvvnb98veh2IZDEKvFyZwRe+f4A9I3eKlF610t0d4HsVJlDh4iEG2AqMG4WWpCPymdk5aFXXrDzQcWNiD95r2eEbwjOJPMr+WxIiTZwNN7WT2QPlZRotGKMskQTLuAuQ44Wa3cejrvl3DZ",
		".	86400	IN	DNSKEY	257 3 8 AwEAAcjLi71oV55rThFidre9DgnEgJwOmPPg0XwWmFkz3uNoT3+SaT6hErHuJS2I8+vc4rZIoGaNdlOrsNBEqyfaikDniq6+PwdNFK8Adt8xBCh9YOZkexdb8i59MABbv1TtJ130O9L8OQ9MOfJfyLm9UknV4D5y8HDDOBcjkJ2U4DRx",
		".	86400	IN	DNSKEY	257 3 8 AwEAAc78m2ldR7iPdjdFZlGheNgdUclcSrPSx+E5s0XWiW6nBaDDawTICkwWI7m7Uzuva1myKkZKgidtwmmxS1P6/xjsRCn1xEjPXvim5Xzr0gjsp16KFQsR8IALGu6dxJYn7WHB+UdT3yiV0x6FwAVb/ilYsOMmn3S/oaaTx4Oh7OEL",
		".	86400	IN	DNSKEY	385 3 8 AwEAAcZMCRaHx5n6GWwAWFrwhnfheNafQfaoBcn1IfwmQ8RD/0V+WAeFU+CVH+zinmqamv/V+zF2FF03WZjuq5HpOtqFVAKsQmC3Wb6DttjwzgNs0Iywgy/Ae8QZp03WApVmzcr4hDvxXeP5ABMwf8vR7gF/JtArb2Mlnekh/7sWs/wr",
	}
	cfg.Maxdepth = 30
	cfg.Expire = 600
	cfg.CacheSize = 1024
	cfg.Timeout.Duration = 2 * time.Second
	cfg.Directory = filepath.Join(os.TempDir(), "sdns_temp_autota")
	cfg.IPv6Access = false

	_ = os.Mkdir(cfg.Directory, 0777)

	return cfg
}

func runTestServer() {
	buf, _ := base64.StdEncoding.DecodeString(privateKey)
	privKey, _ := x509.ParsePKCS1PrivateKey(buf)

	dnskey1 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		Algorithm: 8,
		Flags:     257,
		Protocol:  3,
		PublicKey: "AwEAAZYgqI4XH8upWmlpRJ9bZr2ESd9RL5Bvvnb98veh2IZDEKvFyZwRe+f4A9I3eKlF610t0d4HsVJlDh4iEG2AqMG4WWpCPymdk5aFXXrDzQcWNiD95r2eEbwjOJPMr+WxIiTZwNN7WT2QPlZRotGKMskQTLuAuQ44Wa3cejrvl3DZ",
	}

	dnskey2 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		Algorithm: 8,
		Flags:     385,
		Protocol:  3,
		PublicKey: "AwEAAcjLi71oV55rThFidre9DgnEgJwOmPPg0XwWmFkz3uNoT3+SaT6hErHuJS2I8+vc4rZIoGaNdlOrsNBEqyfaikDniq6+PwdNFK8Adt8xBCh9YOZkexdb8i59MABbv1TtJ130O9L8OQ9MOfJfyLm9UknV4D5y8HDDOBcjkJ2U4DRx",
	}

	rrsigdk := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		TypeCovered: dns.TypeDNSKEY,
		Algorithm:   8,
		SignerName:  ".",
		KeyTag:      dnskey1.KeyTag(),
		Inception:   uint32(time.Now().UTC().Unix()),
		Expiration:  uint32(time.Now().UTC().Add(15 * 24 * time.Hour).Unix()),
		OrigTtl:     3600,
	}

	dnskey3 := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    86400,
		},
		Algorithm: 8,
		Flags:     257,
		Protocol:  3,
	}

	_, _ = dnskey3.Generate(1024)

	_ = rrsigdk.Sign(privKey, []dns.RR{dnskey1, dnskey2, dnskey3})

	/*if s, ok := privkey.(*rsa.PrivateKey); ok {
		buf := x509.MarshalPKCS1PrivateKey(s)
		fmt.Println(base64.StdEncoding.EncodeToString(buf))
		rrsig.Sign(s, []dns.RR{dnskey})
	}*/

	go func() {
		_ = dns.ListenAndServe("127.0.0.1:44302", "udp", &dummyHandler{DNSKEY: []dns.RR{dnskey1, dnskey2, dnskey3, rrsigdk}})
	}()
}

func Test_autota(t *testing.T) {
	runTestServer()

	cfg := makeRootKeysConfig()

	r := resolver.NewResolver(cfg)

	time.Sleep(time.Second)

	req := new(dns.Msg)
	req.SetQuestion(".", dns.TypeDNSKEY)
	req.SetEdns0(1400, true)

	rootservers := &authcache.AuthServers{}
	rootservers.Zone = "."

	for _, s := range cfg.RootServers {
		host, _, _ := net.SplitHostPort(s)
		if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
			rootservers.List = append(rootservers.List, authcache.NewAuthServer(s, authcache.IPv4))
		}
	}

	resp, err := r.Resolve(context.Background(), req, rootservers, true, 30, 0, false, nil)

	assert.True(t, resp.AuthenticatedData)
	assert.NoError(t, err)
	assert.Len(t, resp.Answer, 4)

	os.Remove(filepath.Join(cfg.Directory, "trust-anchor.db"))
}
