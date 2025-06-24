package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCertManager(t *testing.T) {
	// Create temp directory for test certificates
	tmpDir, err := os.MkdirTemp("", "certmanager-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate initial certificate
	cert1, key1 := generateTestCert(t, "test1.example.com")
	writeCertAndKey(t, certPath, keyPath, cert1, key1)

	// Create certificate manager
	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Verify initial certificate
	tlsConfig := cm.GetTLSConfig()
	require.NotNil(t, tlsConfig)

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate subject
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "test1.example.com", x509Cert.Subject.CommonName)

	// Generate new certificate
	cert2, key2 := generateTestCert(t, "test2.example.com")

	// Wait a bit to ensure file modification time changes
	time.Sleep(10 * time.Millisecond)

	// Replace certificate files
	writeCertAndKey(t, certPath, keyPath, cert2, key2)

	// Wait for watcher to detect change
	time.Sleep(100 * time.Millisecond)

	// Verify certificate was reloaded
	cert, err = cm.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert)

	x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "test2.example.com", x509Cert.Subject.CommonName)
}

func TestCertManagerReload(t *testing.T) {
	// Create temp directory for test certificates
	tmpDir, err := os.MkdirTemp("", "certmanager-reload-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate initial certificate
	cert1, key1 := generateTestCert(t, "reload1.example.com")
	writeCertAndKey(t, certPath, keyPath, cert1, key1)

	// Create certificate manager
	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Generate new certificate
	cert2, key2 := generateTestCert(t, "reload2.example.com")
	writeCertAndKey(t, certPath, keyPath, cert2, key2)

	// Force reload
	err = cm.Reload()
	require.NoError(t, err)

	// Verify certificate was reloaded
	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	require.NoError(t, err)
	require.NotNil(t, cert)

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	require.NoError(t, err)
	assert.Equal(t, "reload2.example.com", x509Cert.Subject.CommonName)
}

func generateTestCert(t *testing.T, commonName string) ([]byte, []byte) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	require.NoError(t, err)

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM
}

func writeCertAndKey(t *testing.T, certPath, keyPath string, cert, key []byte) {
	err := os.WriteFile(certPath, cert, 0644)
	require.NoError(t, err)

	err = os.WriteFile(keyPath, key, 0600)
	require.NoError(t, err)
}
