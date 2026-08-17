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
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/semihalev/sdns/config"
)

func TestCertManager(t *testing.T) {
	// Create temp directory for test certificates
	tmpDir, err := os.MkdirTemp("", "certmanager-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate initial certificate
	cert1, key1 := generateTestCert(t, "test1.example.com")
	writeCertAndKey(t, certPath, keyPath, cert1, key1)

	// Create certificate manager
	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Verify initial certificate
	tlsConfig := cm.GetTLSConfig()
	if tlsConfig == nil {
		t.Fatalf("tlsConfig is nil")
	}

	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatalf("cert is nil")
	}

	// Verify certificate subject
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual("test1.example.com", x509Cert.Subject.CommonName) {
		t.Errorf("x509Cert.Subject.CommonName = %v, want %v", x509Cert.Subject.CommonName, "test1.example.com")
	}

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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cert == nil {
			t.Fatalf("cert is nil")
		}

		x509Cert, err = x509.ParseCertificate(cert.Certificate[0])
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if x509Cert.Subject.CommonName == "test2.example.com" {
			break
		}

		if i == maxRetries-1 {
			t.Fatalf("Certificate not reloaded after %d attempts, still shows: %s", maxRetries, x509Cert.Subject.CommonName)
		}
	}

	if !reflect.DeepEqual("test2.example.com", x509Cert.Subject.CommonName) {
		t.Errorf("x509Cert.Subject.CommonName = %v, want %v", x509Cert.Subject.CommonName, "test2.example.com")
	}
}

func TestCertManagerReload(t *testing.T) {
	// Create temp directory for test certificates
	tmpDir, err := os.MkdirTemp("", "certmanager-reload-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	// Generate initial certificate
	cert1, key1 := generateTestCert(t, "reload1.example.com")
	writeCertAndKey(t, certPath, keyPath, cert1, key1)

	// Create certificate manager
	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Generate new certificate
	cert2, key2 := generateTestCert(t, "reload2.example.com")
	writeCertAndKey(t, certPath, keyPath, cert2, key2)

	// Force reload
	err = cm.Reload()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify certificate was reloaded
	cert, err := cm.GetCertificate(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cert == nil {
		t.Fatalf("cert is nil")
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !reflect.DeepEqual("reload2.example.com", x509Cert.Subject.CommonName) {
		t.Errorf("x509Cert.Subject.CommonName = %v, want %v", x509Cert.Subject.CommonName, "reload2.example.com")
	}
}

func generateTestCert(t *testing.T, commonName string) ([]byte, []byte) {
	// Generate private key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Encode certificate
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode private key
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: keyDER,
	})

	return certPEM, keyPEM
}

func writeCertAndKey(t *testing.T, certPath, keyPath string, cert, key []byte) {
	err := os.WriteFile(certPath, cert, 0644) //nolint:gosec // G306 - test file
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	err = os.WriteFile(keyPath, key, 0600)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCertManagerErrors(t *testing.T) {
	t.Run("NonExistentFiles", func(t *testing.T) {
		cm, err := NewCertManager("/nonexistent/cert.pem", "/nonexistent/key.pem")
		if err == nil {
			t.Errorf("expected an error, got nil")
		}
		if cm != nil {
			t.Errorf("cm = %v, want nil", cm)
		}
	})

	t.Run("InvalidCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-error-test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "invalid.crt")
		keyPath := filepath.Join(tmpDir, "invalid.key")

		// Write invalid certificate data
		err = os.WriteFile(certPath, []byte("invalid cert data"), 0644) //nolint:gosec // G306 - test file
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		err = os.WriteFile(keyPath, []byte("invalid key data"), 0600)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		cm, err := NewCertManager(certPath, keyPath)
		if err == nil {
			t.Errorf("expected an error, got nil")
		}
		if cm != nil {
			t.Errorf("cm = %v, want nil", cm)
		}
	})

	t.Run("ExpiredCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-expired-test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "expired.crt")
		keyPath := filepath.Join(tmpDir, "expired.key")

		// Generate expired certificate
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})

		writeCertAndKey(t, certPath, keyPath, certPEM, keyPEM)

		cm, err := NewCertManager(certPath, keyPath)
		if err == nil {
			t.Errorf("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "certificate expired") {
			t.Errorf("%q does not contain %q", err.Error(), "certificate expired")
		}
		if cm != nil {
			t.Errorf("cm = %v, want nil", cm)
		}
	})

	t.Run("NotYetValidCertificate", func(t *testing.T) {
		tmpDir, err := os.MkdirTemp("", "certmanager-notyet-test")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer os.RemoveAll(tmpDir)

		certPath := filepath.Join(tmpDir, "notyet.crt")
		keyPath := filepath.Join(tmpDir, "notyet.key")

		// Generate not yet valid certificate
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

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
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certDER,
		})

		keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})

		writeCertAndKey(t, certPath, keyPath, certPEM, keyPEM)

		cm, err := NewCertManager(certPath, keyPath)
		if err == nil {
			t.Errorf("expected an error, got nil")
		}
		if !strings.Contains(err.Error(), "certificate not yet valid") {
			t.Errorf("%q does not contain %q", err.Error(), "certificate not yet valid")
		}
		if cm != nil {
			t.Errorf("cm = %v, want nil", cm)
		}
	})
}

func TestCertManagerWatcherErrors(t *testing.T) {
	// Test directory watch failure
	tmpDir, err := os.MkdirTemp("", "certmanager-watcher-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "watcher.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Remove the directory to cause stat errors
	os.RemoveAll(tmpDir) //nolint:gosec // G104 - test cleanup

	// Trigger checkAndReload - should handle error gracefully
	cm.checkAndReload()

	// Certificate should still be accessible
	tlsCert, err := cm.GetCertificate(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if tlsCert == nil {
		t.Fatalf("tlsCert is nil")
	}
}

func TestCertManagerConcurrency(t *testing.T) {
	if testing.Short() || os.Getenv("CI") == "true" {
		t.Skip("Skipping flaky concurrency test in CI/short mode")
	}

	tmpDir, err := os.MkdirTemp("", "certmanager-concurrent-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "concurrent.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Run concurrent operations
	done := make(chan bool)

	// Multiple readers
	for i := 0; i < 10; i++ {
		go func() {
			for j := 0; j < 100; j++ {
				cert, err := cm.GetCertificate(nil)
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if cert == nil {
					// Errorf, not Fatalf: FailNow must not run off the
					// test goroutine.
					t.Errorf("cert is nil")
					break
				}
			}
			done <- true
		}()
	}

	// Concurrent reloads. The write+reload pairs are serialized against
	// each other: two goroutines rewriting the same PEM files can hand
	// Reload a torn certificate, which is a bug in the test, not in the
	// manager — the concurrency under test is readers racing reloads,
	// and that stays fully concurrent. (This flaked ~1 run in 10 on an
	// untouched tree too; it just went unnoticed.)
	var reloadMu sync.Mutex
	for i := 0; i < 3; i++ {
		go func(id int) {
			for j := 0; j < 10; j++ {
				reloadMu.Lock()
				// Generate new cert for each reload
				cert, key := generateTestCert(t, "concurrent-reload.example.com")
				writeCertAndKey(t, certPath, keyPath, cert, key)

				err := cm.Reload()
				reloadMu.Unlock()
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "config.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Get multiple TLS configs
	config1 := cm.GetTLSConfig()
	config2 := cm.GetTLSConfig()

	// Should return fresh configs each time
	if config1 == config2 {
		t.Errorf("%p is the same pointer", config1)
	}

	// Both should work correctly
	if config1.GetCertificate == nil {
		t.Fatalf("config1.GetCertificate is nil")
	}
	if config2.GetCertificate == nil {
		t.Fatalf("config2.GetCertificate is nil")
	}
	if !reflect.DeepEqual(uint16(tls.VersionTLS12), config1.MinVersion) {
		t.Errorf("config1.MinVersion = %v, want %v", config1.MinVersion, uint16(tls.VersionTLS12))
	}
	if !reflect.DeepEqual(uint16(tls.VersionTLS12), config2.MinVersion) {
		t.Errorf("config2.MinVersion = %v, want %v", config2.MinVersion, uint16(tls.VersionTLS12))
	}
}

func TestReloadWithRetry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certmanager-retry-test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "test.crt")
	keyPath := filepath.Join(tmpDir, "test.key")

	cert, key := generateTestCert(t, "retry.example.com")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	cm, err := NewCertManager(certPath, keyPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer cm.Stop()

	// Remove certificate to cause reload failure
	os.Remove(certPath) //nolint:gosec // G104 - test cleanup

	// This should fail after retries
	err = cm.reloadWithRetry()
	if err == nil {
		t.Errorf("expected an error, got nil")
	}
	if !strings.Contains(err.Error(), "failed after 3 attempts") {
		t.Errorf("%q does not contain %q", err.Error(), "failed after 3 attempts")
	}
}

// A stopped Server must never grow a new certificate manager: the DoQ
// listener used to fetch its TLS config at serve time, and a Serve
// goroutine racing a fast start-then-cancel could ask the provider
// after Stop had already torn the manager down — a fresh file watcher
// behind a Stopped() that had said true.
func TestGetTLSConfigRefusedAfterStop(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := dir+"/cert.pem", dir+"/key.pem"
	cert, key := generateTestCert(t, "stop.test")
	writeCertAndKey(t, certPath, keyPath, cert, key)

	s := New(&config.Config{Bind: "127.0.0.1:0", TLSCertificate: certPath, TLSPrivateKey: keyPath})

	if s.GetTLSConfig() == nil {
		t.Fatal("provider refused a valid certificate before stop")
	}
	s.Stop()
	if s.GetTLSConfig() != nil {
		t.Fatal("a stopped provider built a TLS config — and the manager and watcher behind it")
	}
	s.certMu.Lock()
	cm := s.certManager
	s.certMu.Unlock()
	if cm != nil {
		t.Fatal("a certificate manager exists after Stop")
	}
}
