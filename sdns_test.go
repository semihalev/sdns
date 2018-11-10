package main

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/semihalev/log"
	"github.com/semihalev/sdns/blocklist"
	"github.com/semihalev/sdns/config"
	"github.com/stretchr/testify/assert"
)

const (
	testDomain = "www.google.com"
)

func TestMain(m *testing.M) {
	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	Config = new(config.Config)
	Config.RootServers = []string{"192.5.5.241:53"}
	Config.RootKeys = []string{
		".			172800	IN	DNSKEY	257 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjFFVQUTf6v58fLjwBd0YI0EzrAcQqBGCzh/RStIoO8g0NfnfL2MTJRkxoXbfDaUeVPQuYEhg37NZWAJQ9VnMVDxP/VHL496M/QZxkjf5/Efucp2gaDX6RS6CXpoY68LsvPVjR0ZSwzz1apAzvN9dlzEheX7ICJBBtuA6G3LQpzW5hOA2hzCTMjJPJ8LbqF6dsV6DoBQzgul0sGIcGOYl7OyQdXfZ57relSQageu+ipAdTTJ25AsRTAoub8ONGcLmqrAmRLKBP1dfwhYB4N7knNnulqQxA+Uk1ihz0=",
		".			172800	IN	DNSKEY	256 3 8 AwEAAdp440E6Mz7c+Vl4sPd0lTv2Qnc85dTW64j0RDD7sS/zwxWDJ3QRES2VKDO0OXLMqVJSs2YCCSDKuZXpDPuf++YfAu0j7lzYYdWTGwyNZhEaXtMQJIKYB96pW6cRkiG2Dn8S2vvo/PxW9PKQsyLbtd8PcwWglHgReBVp7kEv/Dd+3b3YMukt4jnWgDUddAySg558Zld+c9eGWkgWoOiuhg4rQRkFstMX1pRyOSHcZuH38o1WcsT4y3eT0U/SR6TOSLIB/8Ftirux/h297oS7tCcwSPt0wwry5OFNTlfMo8v7WGurogfk8hPipf7TTKHIi20LWen5RCsvYsQBkYGpF78=",
	}
	Config.Maxdepth = 30
	Config.Expire = 600
	Config.Timeout.Duration = 2 * time.Second
	Config.ConnectTimeout.Duration = 2 * time.Second
	Config.Nullroute = "0.0.0.0"
	Config.Nullroutev6 = "0:0:0:0:0:0:0:0"
	Config.Bind = ":0"
	Config.BindTLS = ""
	Config.BindDOH = ""
	Config.API = ""

	m.Run()
}

func Test_Blocklist(t *testing.T) {
	tempDir := filepath.Join(os.TempDir(), "/sdns_temp")

	Config.Whitelist = append(Config.Whitelist, testDomain)
	Config.Blocklist = append(Config.Blocklist, testDomain)

	Config.BlockLists = []string{}
	Config.BlockLists = append(Config.BlockLists, "https://raw.githubusercontent.com/quidsup/notrack/master/trackers.txt")
	Config.BlockLists = append(Config.BlockLists, "https://test.dev/hosts")

	blocklist := blocklist.New(Config)

	err := updateBlocklists(blocklist, tempDir)
	assert.NoError(t, err)

	err = readBlocklists(blocklist, tempDir)
	assert.NoError(t, err)
}

func Test_start(t *testing.T) {
	err := generateCertificate()
	assert.NoError(t, err)

	setup()

	Config.TLSCertificate = "test.cert"
	Config.TLSPrivateKey = "test.key"
	Config.LogLevel = "crit"
	Config.Bind = "127.0.0.1:0"
	Config.API = "127.0.0.1:23221"
	Config.BindTLS = "127.0.0.1:23222"
	Config.BindDOH = "127.0.0.1:23223"

	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	run()
	time.Sleep(2 * time.Second)

	os.Remove("test.cert")
	os.Remove("test.key")

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	flag.Usage()
	os.Stderr = stderr
}

/*func BenchmarkExchange(b *testing.B) {
	s, addrstr, err := RunLocalUDPServer("127.0.0.1:0")
	assert.NoError(b, err)

	defer s.Shutdown()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true

	c := new(dns.Client)

	//caching
	_, _, err = c.Exchange(req, addrstr)
	assert.NoError(b, err)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		c.Exchange(req, addrstr)
	}
}

func BenchmarkResolver(b *testing.B) {
	r := NewResolver()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("www.netdirekt.com.tr"), dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(DefaultMsgSize, true)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		r.Resolve("udp", req, rootservers, true, 30, 0, false, nil)
	}
}

func BenchmarkUDPHandler(b *testing.B) {
	h := NewDNSHandler()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true
	req.SetEdns0(DefaultMsgSize, true)

	//caching
	resp := h.query("udp", req)
	assert.NotNil(b, resp)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.query("udp", req)
	}
}

func BenchmarkTCPHandler(b *testing.B) {
	h := NewDNSHandler()

	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn(testDomain), dns.TypeA)
	req.RecursionDesired = true

	//caching
	resp := h.query("tcp", req)
	assert.NotNil(b, resp)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h.query("tcp", req)
	}
}*/
