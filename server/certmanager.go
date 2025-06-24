package server

import (
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/semihalev/zlog"
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
}

// NewCertManager creates a new certificate manager
func NewCertManager(certPath, keyPath string) (*CertManager, error) {
	cm := &CertManager{
		certPath: certPath,
		keyPath:  keyPath,
		stopCh:   make(chan struct{}),
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
	cm.watcher = watcher

	// Watch certificate directory (not the files directly, as they might be symlinks)
	certDir := filepath.Dir(certPath)
	keyDir := filepath.Dir(keyPath)

	if err := watcher.Add(certDir); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to watch certificate directory: %w", err)
	}

	if certDir != keyDir {
		if err := watcher.Add(keyDir); err != nil {
			watcher.Close()
			return nil, fmt.Errorf("failed to watch key directory: %w", err)
		}
	}

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

	cm.mu.RLock()
	lastMod := cm.lastModTime
	cm.mu.RUnlock()

	if certInfo.ModTime().After(lastMod) {
		zlog.Info("Certificate file changed, reloading", "path", cm.certPath)
		if err := cm.Reload(); err != nil {
			zlog.Error("Failed to reload certificate", "error", err.Error())
		}
	}
}

// Reload forces a certificate reload
func (cm *CertManager) Reload() error {
	return cm.loadCertificate()
}

// Stop stops the certificate manager
func (cm *CertManager) Stop() {
	close(cm.stopCh)
}
