// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CertReloadInterval is how often a CertReloader looks at its files (G0 M13
// D4: polling, no file-notification dependency).
const CertReloadInterval = 60 * time.Second

// CertReloader serves a TLS key pair read from files and picks up a renewed
// pair without a restart (HR-371). GetCertificate always serves the last
// good pair: a reload swaps it only when both files parse as a matching pair
// whose leaf certificate is valid now, and a failed reload keeps the last
// good pair and logs tls.reload_failed without key material. Any listener
// with file certificates can use one.
type CertReloader struct {
	certFile, keyFile string
	log               *slog.Logger
	now               func() time.Time

	mu      sync.RWMutex
	current *tls.Certificate
	// seen is the state of the files last read, good or not, so a pair
	// that failed is not read again until a file changes.
	seen [2]fileStamp
}

type fileStamp struct {
	mod  time.Time
	size int64
}

func stampOf(path string) (fileStamp, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, err
	}
	return fileStamp{mod: fi.ModTime(), size: fi.Size()}, nil
}

// NewCertReloader reads the pair once; it fails when the pair cannot be
// loaded, so a listener never starts without a certificate.
func NewCertReloader(certFile, keyFile string, log *slog.Logger) (*CertReloader, error) {
	if log == nil {
		log = pclog.Discard()
	}
	r := &CertReloader{certFile: certFile, keyFile: keyFile, log: log, now: time.Now}
	stamps, err := r.stamps()
	if err != nil {
		return nil, fmt.Errorf("httpx: TLS key pair: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("httpx: TLS key pair: %w", err)
	}
	r.current, r.seen = &cert, stamps
	return r, nil
}

func (r *CertReloader) stamps() ([2]fileStamp, error) {
	c, err := stampOf(r.certFile)
	if err != nil {
		return [2]fileStamp{}, err
	}
	k, err := stampOf(r.keyFile)
	if err != nil {
		return [2]fileStamp{}, err
	}
	return [2]fileStamp{c, k}, nil
}

// GetCertificate implements tls.Config.GetCertificate: the last good pair.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.Certificate(), nil
}

// Certificate returns the pair being served.
func (r *CertReloader) Certificate() *tls.Certificate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.current
}

// errUnchanged reports that neither file changed since the last read.
var errUnchanged = errors.New("httpx: TLS files unchanged")

// Reload reads the files again when either changed (modification time or
// size) and swaps the served pair when the new one is good. It reports
// whether it swapped; a bad pair keeps the last good one and is logged.
func (r *CertReloader) Reload(ctx context.Context) bool {
	err := r.reload()
	switch {
	case err == nil:
		r.log.InfoContext(ctx, "tls.reloaded")
		return true
	case errors.Is(err, errUnchanged):
		return false
	default:
		// The error names the file problem only: tls and x509 errors never
		// carry key material.
		r.log.WarnContext(ctx, "tls.reload_failed", slog.String("reason", err.Error()))
		return false
	}
}

func (r *CertReloader) reload() error {
	stamps, err := r.stamps()
	if err != nil {
		return err
	}
	r.mu.RLock()
	same := stamps == r.seen
	r.mu.RUnlock()
	if same {
		return errUnchanged
	}
	r.mu.Lock()
	r.seen = stamps
	r.mu.Unlock()
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	leaf := cert.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return err
		}
	}
	if now := r.now(); now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return fmt.Errorf("certificate is not valid now (valid %s to %s)",
			leaf.NotBefore.UTC().Format(time.RFC3339), leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	r.mu.Lock()
	r.current = &cert
	r.mu.Unlock()
	return nil
}

// Run polls the files every interval until ctx ends.
func (r *CertReloader) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.Reload(ctx)
		}
	}
}

// ReloadingServerTLSConfig is ServerTLSConfig with the certificate taken
// from r on every handshake.
func ReloadingServerTLSConfig(r *CertReloader) *tls.Config {
	c := ServerTLSConfig(tls.Certificate{})
	c.Certificates = nil
	c.GetCertificate = r.GetCertificate
	return c
}
