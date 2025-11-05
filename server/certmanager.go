package server

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/semihalev/zlog/v2"
)

// CertManager manages TLS certificates with automatic reloading
type CertManager struct {
	certPath string
	keyPath  string

	mu          sync.RWMutex
	certificate *tls.Certificate
	lastModTime time.Time

	watcher *fsnotify.Watcher
	stopCh  chan struct{}
	doneCh  chan struct{}
}

// NewCertManager creates a new certificate manager
func NewCertManager(certPath, keyPath string) (*CertManager, error) {
	cm := &CertManager{
		certPath: certPath,
		keyPath:  keyPath,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}

	// Load initial certificate
	if err := cm.loadCertificate(); err != nil {
		return nil, fmt.Errorf("failed to load initial certificate: %w", err)
	}

	// Create file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create watcher: %w", err)
	}

	// Watch certificate directory (not the files directly, as they might be symlinks)
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := watcher.Add(certDir); err != nil {
		watcher.Close() //nolint:gosec // G104 - cleanup on error path
		return nil, fmt.Errorf("failed to watch certificate directory: %w", err)
	}

	if certDir != keyDir {
		if err := watcher.Add(keyDir); err != nil {
			// Remove the first directory watch before closing
			watcher.Remove(certDir) //nolint:gosec // G104 - cleanup on error path
			watcher.Close()         //nolint:gosec // G104 - cleanup on error path
			return nil, fmt.Errorf("failed to watch key directory: %w", err)
		}
	}

	// Only assign watcher after all directories are successfully watched
	cm.watcher = watcher

	// Start watching
	go cm.watch()

	return cm, nil
}

// loadCertificate loads the certificate from disk
func (cm *CertManager) loadCertificate() error {
	cert, err := tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	if err != nil {
		return err
	}

	// Validate certificate
	if err := cm.validateCertificate(&cert); err != nil {
		return fmt.Errorf("certificate validation failed: %w", err)
	}

	// Get modification time for change detection
	certInfo, err := os.Stat(cm.certPath)
	if err != nil {
		return err
	}

	cm.mu.Lock()
	cm.certificate = &cert
	cm.lastModTime = certInfo.ModTime()
	cm.mu.Unlock()

	zlog.Info("TLS certificate loaded", "cert", cm.certPath, "modTime", certInfo.ModTime())

	return nil
}

// validateCertificate validates the certificate chain and expiration
func (cm *CertManager) validateCertificate(cert *tls.Certificate) error {
	if cert == nil || len(cert.Certificate) == 0 {
		return fmt.Errorf("empty certificate chain")
	}

	// Parse the leaf certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		return fmt.Errorf("certificate not yet valid (not before: %v)", x509Cert.NotBefore)
	}
	if now.After(x509Cert.NotAfter) {
		return fmt.Errorf("certificate expired (not after: %v)", x509Cert.NotAfter)
	}

	// Warn if certificate expires soon (within 7 days)
	daysUntilExpiry := x509Cert.NotAfter.Sub(now).Hours() / 24
	if daysUntilExpiry < 7 {
		zlog.Warn("Certificate expires soon", "days", int(daysUntilExpiry), "expiry", x509Cert.NotAfter)
	}

	return nil
}

// GetCertificate returns the current certificate
func (cm *CertManager) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	if cm.certificate == nil {
		return nil, fmt.Errorf("no certificate available")
	}

	return cm.certificate, nil
}

// GetTLSConfig returns a TLS config that uses dynamic certificate loading
// Each call returns a fresh config to avoid race conditions
func (cm *CertManager) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: cm.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}
}

// watch monitors for certificate changes
func (cm *CertManager) watch() {
	defer close(cm.doneCh)
	defer cm.watcher.Close()

	// Also check periodically in case fsnotify misses events
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-cm.stopCh:
			return

		case event, ok := <-cm.watcher.Events:
			if !ok {
				return
			}

			// Check if our files were affected
			if cm.isRelevantEvent(event) {
				zlog.Debug("Certificate file event", "event", event.String())
				cm.checkAndReload()
			}

		case err, ok := <-cm.watcher.Errors:
			if !ok {
				return
			}
			zlog.Error("Certificate watcher error", "error", err.Error())

		case <-ticker.C:
			// Periodic check
			cm.checkAndReload()
		}
	}
}

// isRelevantEvent checks if the event is for our certificate files
func (cm *CertManager) isRelevantEvent(event fsnotify.Event) bool {
	eventPath := event.Name

	// Handle both direct file changes and symlink updates (common with Let's Encrypt)
	certName := filepath.Base(cm.certPath)
	keyName := filepath.Base(cm.keyPath)
	eventName := filepath.Base(eventPath)

	return eventName == certName || eventName == keyName ||
		eventPath == cm.certPath || eventPath == cm.keyPath
}

// checkAndReload checks if certificate needs reloading
func (cm *CertManager) checkAndReload() {
	// Check if certificate file has been modified
	certInfo, err := os.Stat(cm.certPath)
	if err != nil {
		zlog.Error("Failed to stat certificate file", "path", cm.certPath, "error", err.Error())
		return
	}

	// Use a single lock to prevent race between check and reload
	cm.mu.Lock()
	shouldReload := certInfo.ModTime().After(cm.lastModTime)
	cm.mu.Unlock()

	if shouldReload {
		zlog.Info("Certificate file changed, reloading", "path", cm.certPath)
		if err := cm.reloadWithRetry(); err != nil {
			zlog.Error("Failed to reload certificate after retries", "error", err.Error())
		}
	}
}

// reloadWithRetry attempts to reload the certificate with retry logic
func (cm *CertManager) reloadWithRetry() error {
	const maxRetries = 3
	const retryDelay = time.Second

	var lastErr error
	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			zlog.Warn("Retrying certificate reload", "attempt", i+1, "max", maxRetries)
			time.Sleep(retryDelay)
		}

		if err := cm.Reload(); err != nil {
			lastErr = err
			continue
		}

		return nil
	}

	return fmt.Errorf("failed after %d attempts: %w", maxRetries, lastErr)
}

// Reload forces a certificate reload
func (cm *CertManager) Reload() error {
	return cm.loadCertificate()
}

// Stop stops the certificate manager and waits for cleanup
func (cm *CertManager) Stop() {
	close(cm.stopCh)
	// Wait for the watcher goroutine to finish
	<-cm.doneCh
}
