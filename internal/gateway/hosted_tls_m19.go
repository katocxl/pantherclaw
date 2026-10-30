// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// hostedTLS is a hosted gateway's agent-facing certificate (G0 M19 D210):
// an Ed25519 key generated in the gateway's own volume (tls.key_file),
// never sent anywhere, and a 7-day certificate for exactly
// <slug>.gw.<domain> from the gateway CA, asked for over the gateway's own
// mTLS identity and renewed at two thirds of its lifetime.
type hostedTLS struct {
	keyFile, certFile string
	key               ed25519.PrivateKey
	cur               atomic.Pointer[tls.Certificate]
	issue             func(ctx context.Context, csr []byte) ([]byte, error)
	log               *slog.Logger
	now               func() time.Time
}

// newHostedTLS loads or makes the key and loads or fetches the certificate.
func newHostedTLS(ctx context.Context, cfg *Config, log *slog.Logger) (*hostedTLS, error) {
	if cfg.TLS.KeyFile == "" || cfg.TLS.CertFile == "" {
		return nil, errors.New("gateway: a hosted gateway needs tls.key_file and tls.cert_file in its volume")
	}
	key, err := loadOrMakeKey(cfg.TLS.KeyFile)
	if err != nil {
		return nil, err
	}
	h := &hostedTLS{keyFile: cfg.TLS.KeyFile, certFile: cfg.TLS.CertFile, key: key, log: log, now: time.Now}
	h.issue = func(ctx context.Context, csr []byte) ([]byte, error) {
		hc := httpx.NewControlClient(httpx.ControlConfig{
			Timeout: cfg.Control.Timeout.D(), Link: "gateway-control", Log: log,
			RootCAs: rootsOf(cfg),
			ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				// The identity on disk is the current one: the control
				// client renews and saves it.
				id, err := control.Load(cfg.Control.IdentityDir, cfg.Control.CASHA256)
				if err != nil {
					return nil, err
				}
				c := id.TLSCertificate()
				return &c, nil
			},
		})
		cli := pantherclawv1connect.NewHostedGatewayIdentityServiceClient(
			connect.NewClient(connecthttp.NewTransport(hc, strings.TrimSuffix(cfg.Control.APIURL, "/"))))
		res, err := cli.IssueServerCertificate(ctx, &pb.IssueServerCertificateRequest{Csr: csr})
		if err != nil {
			return nil, err
		}
		return res.GetCertificate(), nil
	}
	if c, err := h.loadCert(); err == nil && !h.due(c) {
		h.cur.Store(c)
		return h, nil
	}
	if err := h.renew(ctx); err != nil {
		return nil, err
	}
	return h, nil
}

// rootsOf trusts only the pinned internal CA of the saved identity.
func rootsOf(cfg *Config) *x509.CertPool {
	id, err := control.Load(cfg.Control.IdentityDir, cfg.Control.CASHA256)
	if err != nil {
		return x509.NewCertPool() // trusts nothing: the call fails closed
	}
	return id.Roots()
}

func loadOrMakeKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // G304: the gateway's own volume
	if err == nil {
		blk, _ := pem.Decode(b)
		if blk == nil {
			return nil, errors.New("gateway: unreadable tls key")
		}
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if ek, ok := k.(ed25519.PrivateKey); err == nil && ok {
			return ek, nil
		}
		return nil, errors.New("gateway: the tls key is not Ed25519")
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := writePrivate(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})); err != nil {
		return nil, err
	}
	return key, nil
}

// writePrivate writes a 0600 file in a 0700 directory, atomically.
func writePrivate(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func (h *hostedTLS) loadCert() (*tls.Certificate, error) {
	b, err := os.ReadFile(h.certFile)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("gateway: unreadable tls certificate")
	}
	return h.certificate(blk.Bytes)
}

func (h *hostedTLS) certificate(der []byte) (*tls.Certificate, error) {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	if pub, ok := leaf.PublicKey.(ed25519.PublicKey); !ok || !pub.Equal(h.key.Public()) {
		return nil, errors.New("gateway: the tls certificate is not for the gateway's key")
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: h.key, Leaf: leaf}, nil
}

// renewAt is two thirds into the certificate's lifetime.
func renewAt(leaf *x509.Certificate) time.Time {
	return leaf.NotBefore.Add(leaf.NotAfter.Sub(leaf.NotBefore) * 2 / 3)
}

func (h *hostedTLS) due(c *tls.Certificate) bool { return !h.now().Before(renewAt(c.Leaf)) }

// renew asks for a certificate for the same key; only the public key
// leaves the volume, in a certificate request.
func (h *hostedTLS) renew(ctx context.Context) error {
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, h.key)
	if err != nil {
		return err
	}
	der, err := h.issue(ctx, csr)
	if err != nil {
		return fmt.Errorf("gateway: hosted server certificate: %w", err)
	}
	c, err := h.certificate(der)
	if err != nil {
		return err
	}
	if err := writePrivate(h.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
		return err
	}
	h.cur.Store(c)
	h.log.InfoContext(ctx, "gateway.hosted_certificate", slog.String("name", strings.Join(c.Leaf.DNSNames, ",")),
		slog.Time("not_after", c.Leaf.NotAfter))
	return nil
}

// Config is the agent-facing TLS configuration, served from the current
// certificate.
func (h *hostedTLS) Config() *tls.Config {
	c := httpx.ServerTLSConfig(tls.Certificate{})
	c.Certificates = nil
	c.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return h.cur.Load(), nil }
	return c
}

// Run renews at two thirds of each certificate's lifetime, retrying every
// minute on failure, until ctx ends.
func (h *hostedTLS) Run(ctx context.Context) error {
	for {
		wait := time.Until(renewAt(h.cur.Load().Leaf))
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(max(wait, 0)):
		}
		for {
			err := h.renew(ctx)
			if err == nil || ctx.Err() != nil {
				break
			}
			h.log.WarnContext(ctx, "gateway.hosted_certificate_failed", pclog.Err(err))
			select {
			case <-ctx.Done():
				return nil
			case <-time.After(time.Minute):
			}
		}
	}
}
