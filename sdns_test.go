package main

import (
	"context"
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

	"github.com/stretchr/testify/assert"
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

	keyOut.Close()

	return nil
}

func Test_start(t *testing.T) {
	err := generateCertificate()
	assert.NoError(t, err)

	setup()

	cert := filepath.Join(os.TempDir(), "test.cert")
	privkey := filepath.Join(os.TempDir(), "test.key")

	cfg.TLSCertificate = cert
	cfg.TLSPrivateKey = privkey
	cfg.LogLevel = "crit"
	cfg.Bind = "127.0.0.1:0"
	cfg.API = "127.0.0.1:23221"
	cfg.BindTLS = "127.0.0.1:23222"
	cfg.BindDOH = "127.0.0.1:23223"
	cfg.BindDOQ = "127.0.0.1:23224"

	run(context.Background())
	time.Sleep(2 * time.Second)

	os.Remove(cert)
	os.Remove(privkey)

	stderr := os.Stderr
	os.Stderr, _ = os.Open(os.DevNull)
	flag.Usage()
	os.Stderr = stderr
}
