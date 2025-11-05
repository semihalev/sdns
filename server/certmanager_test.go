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

	// Wait for watcher to detect change and reload with retry
	maxRetries := 20
	for i := 0; i < maxRetries; i++ {
		time.Sleep(100 * time.Millisecond)

		cert, err = cm.GetCertificate(&tls.ClientHelloInfo{})
		require.NoError(t, err)
		require.NotNil(t, cert)

		x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
		require.NoError(t, err)

		if x509Cert.Subject.CommonName == "test2.example.com" {
			break
		}

		if i == maxRetries-1 {
			t.Fatalf("Certificate not reloaded after %d attempts, still shows: %s", maxRetries, x509Cert.Subject.CommonName)
		}
	}

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
	err := os.WriteFile(certPath, cert, 0644) //nolint:gosec // G306 - test file
	require.NoError(t, err)

	err = os.WriteFile(keyPath, key, 0600)
	require.NoError(t, err)
}

func TestCertManagerErrors(t *testing.T) {
	t.Run("NonExistentFiles", func(t *testing.T) {
		cm, err := NewCertManager("/nonexistent/cert.pem", "/nonexistent/key.pem")
		assert.Error(t, err)
		assert.Nil(t, cm)
	})

	t.Run("InvalidCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-error-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "invalid.crt")
		keyPath := filepath.Join(tmpDir, "invalid.key")

		// Write invalid certificate data
		err = os.WriteFile(certPath, []byte("invalid cert data"), 0644) //nolint:gosec // G306 - test file
		require.NoError(t, err)
		err = os.WriteFile(keyPath, []byte("invalid key data"), 0600)
		require.NoError(t, err)

		cm, err := NewCertManager(certPath, keyPath)
		assert.Error(t, err)
		assert.Nil(t, cm)
	})

	t.Run("ExpiredCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-expired-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "expired.crt")
		keyPath := filepath.Join(tmpDir, "expired.key")

		// Generate expired certificate
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "expired.example.com",
			},
			NotBefore:             time.Now().Add(-48 * time.Hour),
			NotAfter:              time.Now().Add(-24 * time.Hour), // Expired
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})

		writeCertAndKey(t, certPath, keyPath, certPEM, keyPEM)

		cm, err := NewCertManager(certPath, keyPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate expired")
		assert.Nil(t, cm)
	})

	t.Run("NotYetValidCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-notyet-test")
		require.NoError(t, err)
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "notyet.crt")
		keyPath := filepath.Join(tmpDir, "notyet.key")

		// Generate not yet valid certificate
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject: pkix.Name{
				CommonName: "notyet.example.com",
			},
			NotBefore:             time.Now().Add(24 * time.Hour), // Not yet valid
			NotAfter:              time.Now().Add(48 * time.Hour),
			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
		require.NoError(t, err)

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		require.NoError(t, err)

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})

		writeCertAndKey(t, certPath, keyPath, certPEM, keyPEM)

		cm, err := NewCertManager(certPath, keyPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "certificate not yet valid")
		assert.Nil(t, cm)
	})
}

func TestCertManagerWatcherErrors(t *testing.T) {
	// Test directory watch failure
	tmpDir, err := os.MkdirTemp("", "certmanager-watcher-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "watcher.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Remove the directory to cause stat errors
	os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup

	// Trigger checkAndReload - should handle error gracefully
	cm.checkAndReload()

	// Certificate should still be accessible
	tlsCert, err := cm.GetCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, tlsCert)
}

func TestCertManagerConcurrency(t *testing.T) {
	if testing.Short() || os.Getenv("CI") == "true" {
		t.Skip("Skipping flaky concurrency test in CI/short mode")
	}

	tmpDir, err := os.MkdirTemp("", "certmanager-concurrent-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "concurrent.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Run concurrent operations
	done := make(chan bool)

	// Multiple readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cert, err := cm.GetCertificate(nil)
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			}
			done <- true
		}()
	}

	// Concurrent reloads
	for i := 0; i < 3; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				// Generate new cert for each reload
				cert, key := generateTestCert(t, "concurrent-reload.example.com")
				writeCertAndKey(t, certPath, keyPath, cert, key)

				err := cm.Reload()
				assert.NoError(t, err)
				time.Sleep(time.Millisecond)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 13; i++ {
		<-done
	}
}

func TestGetTLSConfigFreshness(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certmanager-config-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "config.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Get multiple TLS configs
	config1 := cm.GetTLSConfig()
	config2 := cm.GetTLSConfig()

	// Should return fresh configs each time
	assert.NotSame(t, config1, config2)

	// Both should work correctly
	assert.NotNil(t, config1.GetCertificate)
	assert.NotNil(t, config2.GetCertificate)
	assert.Equal(t, uint16(tls.VersionTLS12), config1.MinVersion)
	assert.Equal(t, uint16(tls.VersionTLS12), config2.MinVersion)
}

func TestReloadWithRetry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certmanager-retry-test")
	require.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "retry.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	require.NoError(t, err)
	defer cm.Stop()

	// Remove certificate to cause reload failure
	os.Remove(certPath) //nolint:gosec // G104 - test cleanup

	// This should fail after retries
	err = cm.reloadWithRetry()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed after 3 attempts")
}
