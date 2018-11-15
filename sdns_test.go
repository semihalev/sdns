package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
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

func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func generateCertificate() error {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 3),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = append(template.DNSNames, "localhost")

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		return err
	}

	certOut, err := os.OpenFile(filepath.Join(os.TempDir(), "test.cert"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}
	certOut.Close()

	keyOut, err := os.OpenFile(filepath.Join(os.TempDir(), "test.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	pem.Encode(keyOut, pemBlockForKey(priv))
	keyOut.Close()

	return nil
}

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

func Test_UpdateBlocklists(t *testing.T) {
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

	cert := filepath.Join(os.TempDir(), "test.cert")
	privkey := filepath.Join(os.TempDir(), "test.key")

	Config.TLSCertificate = cert
	Config.TLSPrivateKey = privkey
	Config.LogLevel = "crit"
	Config.Bind = "127.0.0.1:0"
	Config.API = "127.0.0.1:23221"
	Config.BindTLS = "127.0.0.1:23222"
	Config.BindDOH = "127.0.0.1:23223"

	log.Root().SetHandler(log.LvlFilterHandler(0, log.StdoutHandler))

	run()
	time.Sleep(2 * time.Second)

	os.Remove(cert)
	os.Remove(privkey)

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	flag.Usage()
	os.Stderr = stderr
}
