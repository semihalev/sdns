package doq

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/assert"
)

type dummyHandler struct {
	dns.Handler
}

func makeRR(data string) dns.RR {
	r, _ := dns.NewRR(data)

	return r
}

func (h *dummyHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Answer = append(msg.Answer, makeRR("example.com.		1800	IN	A	0.0.0.0"))

	_ = w.WriteMsg(msg)
}

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
	if err != nil {
		return err
	}

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if err != nil {
		return err
	}

	certOut.Close()

	keyOut, err := os.OpenFile(filepath.Join(os.TempDir(), "test.key"), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}

	err = pem.Encode(keyOut, pemBlockForKey(priv))
	if err != nil {
		return err
	}

	return keyOut.Close()
}

func Test_doq(t *testing.T) {
	err := generateCertificate()
	assert.NoError(t, err)

	cert := filepath.Join(os.TempDir(), "test.cert")
	privkey := filepath.Join(os.TempDir(), "test.key")

	h := &dummyHandler{}

	s := &Server{
		Addr:    "127.0.0.1:45853",
		Handler: h,
	}

	go func() {
		err := s.ListenAndServeQUIC(cert, privkey)
		if err == quic.ErrServerClosed {
			return
		}
		assert.NoError(t, err)
	}()

	time.Sleep(time.Second)

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"doq"},
	}
	conn, err := quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	assert.NoError(t, err)

	stream, err := conn.OpenStreamSync(context.Background())
	assert.NoError(t, err)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)
	req.Id = 0

	buf, err := req.Pack()
	assert.NoError(t, err)

	n, err := stream.Write(addPrefixLen(buf))
	assert.NoError(t, err)
	assert.Greater(t, n, 17)

	err = stream.Close()
	assert.NoError(t, err)

	data, err := io.ReadAll(stream)
	assert.NoError(t, err)

	msg := new(dns.Msg)
	err = msg.Unpack(data[2:])
	assert.NoError(t, err)

	stream, err = conn.OpenStreamSync(context.Background())
	assert.NoError(t, err)

	time.Sleep(6 * time.Second)

	_, err = stream.Write([]byte{0, 0})
	assert.Error(t, err)

	conn, err = quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	assert.NoError(t, err)

	stream, err = conn.OpenStreamSync(context.Background())
	assert.NoError(t, err)

	_, err = stream.Write([]byte{0, 0})
	assert.NoError(t, err)

	err = stream.Close()
	assert.NoError(t, err)

	_, err = io.ReadAll(stream)
	assert.Error(t, err)

	conn, err = quic.DialAddr(context.Background(), s.Addr, tlsConf, nil)
	assert.NoError(t, err)

	stream, err = conn.OpenStreamSync(context.Background())
	assert.NoError(t, err)

	msg = new(dns.Msg)
	msg.SetEdns0(512, true)
	buf, _ = msg.Pack()

	_, err = stream.Write(buf)
	assert.NoError(t, err)

	err = stream.Close()
	assert.NoError(t, err)

	_, err = io.ReadAll(stream)
	assert.Error(t, err)

	err = s.Shutdown()
	assert.NoError(t, err)
}
