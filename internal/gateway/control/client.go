// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package control

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// request makes a new Ed25519 key and a certificate request signed by it.
func request() (ed25519.PrivateKey, []byte, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		return nil, nil, err
	}
	return key, csr, nil
}

// Enroll generates the gateway's key and exchanges the single-use token for
// a certificate at the server's public API (HR-180). The returned CA
// certificate must match pin; the identity is not saved.
func Enroll(ctx context.Context, hc *http.Client, apiURL string, token pclog.Secret[string], pin string) (*Identity, error) {
	key, csr, err := request()
	if err != nil {
		return nil, err
	}
	client := pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(hc, strings.TrimSuffix(apiURL, "/"))))
	res, err := client.Enroll(ctx, &pb.GatewayServiceEnrollRequest{Token: token.Reveal(), Csr: csr})
	if err != nil {
		return nil, fmt.Errorf("control: enroll: %w", err)
	}
	return newIdentity(key, res.GetCertificate(), res.GetCaCertificate(), pin, res.GetGatewayApiUrl())
}

// Client is the gateway's mutual-TLS client to the server's gateway
// listener. It presents the current certificate on every new connection,
// trusts only the internal CA for the server, and renews the certificate
// before it expires.
type Client struct {
	dir string
	log *slog.Logger
	now func() time.Time
	cur atomic.Pointer[Identity]

	baseURL   string
	hc        *http.Client
	Authority pantherclawv1connect.AuthorityServiceClient
	Gateway   pantherclawv1connect.GatewayServiceClient
	// Agents submits an organization scan's findings (G0 M8, HR-209).
	Agents pantherclawv1connect.AgentServiceClient
	// Stream is GatewayService for server streams (no request timeout).
	Stream pantherclawv1connect.GatewayServiceClient
}

// NewClient returns the mTLS client for id. baseURL overrides the gateway
// listener URL from enrollment when set; dir is where renewed identities
// are saved.
func NewClient(id *Identity, dir, baseURL string, timeout time.Duration, log *slog.Logger) *Client {
	if baseURL == "" {
		baseURL = id.GatewayAPIURL
	}
	c := &Client{dir: dir, log: log, now: time.Now, baseURL: strings.TrimSuffix(baseURL, "/")}
	c.cur.Store(id)
	c.hc = httpx.NewControlClient(httpx.ControlConfig{
		Timeout: timeout, RootCAs: id.Roots(), Link: "gateway-control", Log: log,
		ClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			cert := c.cur.Load().TLSCertificate()
			return &cert, nil
		},
	})
	c.Authority = pantherclawv1connect.NewAuthorityServiceClient(connect.NewClient(connecthttp.NewTransport(c.hc, c.baseURL)))
	c.Gateway = pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(c.hc, c.baseURL)))
	c.Agents = pantherclawv1connect.NewAgentServiceClient(connect.NewClient(connecthttp.NewTransport(c.hc, c.baseURL)))
	// Streams share the transport (and so the certificate) but have no
	// whole-request timeout: they end with their context.
	stream := httpx.StreamingClient(c.hc)
	c.Stream = pantherclawv1connect.NewGatewayServiceClient(connect.NewClient(connecthttp.NewTransport(stream, c.baseURL)))
	return c
}

// Identity is the current identity.
func (c *Client) Identity() *Identity { return c.cur.Load() }

// HTTPClient is the mTLS client (for the JWKS on the gateway listener).
func (c *Client) HTTPClient() *http.Client { return c.hc }

// BaseURL is the gateway listener's URL.
func (c *Client) BaseURL() string { return c.baseURL }

// renewRetry bounds how often a failed renewal is retried.
const renewRetry = time.Minute

// Run renews the certificate when two thirds of it are used, retrying
// failures every minute, until ctx ends. An expired certificate cannot be
// renewed: the gateway must enroll again.
func (c *Client) Run(ctx context.Context) error {
	for {
		id := c.cur.Load()
		wait := id.NotBefore().Add(RenewAfter).Sub(c.now())
		t := time.NewTimer(max(wait, 0))
		select {
		case <-ctx.Done():
			t.Stop()
			return nil
		case <-t.C:
		}
		if id.Expired(c.now()) {
			c.log.ErrorContext(ctx, "gateway.certificate_expired", slog.String("note", "enroll again with a new token"))
			return errors.New("control: the gateway certificate expired")
		}
		if err := c.Renew(ctx); err != nil {
			c.log.WarnContext(ctx, "gateway.renewal_failed", pclog.Err(err))
			t := time.NewTimer(min(renewRetry, max(id.NotAfter().Sub(c.now()), time.Second)))
			select {
			case <-ctx.Done():
				t.Stop()
				return nil
			case <-t.C:
			}
		}
	}
}

// Renew gets a certificate for a new key over mTLS, checks it (same CA,
// same gateway and org), switches to it and saves it.
func (c *Client) Renew(ctx context.Context) error {
	old := c.cur.Load()
	key, csr, err := request()
	if err != nil {
		return err
	}
	res, err := c.Gateway.RenewCertificate(ctx, &pb.RenewCertificateRequest{Csr: csr})
	if err != nil {
		return fmt.Errorf("control: renew: %w", err)
	}
	next, err := newIdentity(key, res.GetCertificate(), res.GetCaCertificate(), old.CASHA256, old.GatewayAPIURL)
	if err != nil {
		return err
	}
	if next.Org != old.Org || next.Gateway != old.Gateway {
		return fmt.Errorf("%w: the renewal names another gateway", ErrIdentity)
	}
	c.cur.Store(next)
	if c.dir != "" {
		if err := next.Save(c.dir); err != nil {
			return fmt.Errorf("control: save renewed identity: %w", err)
		}
	}
	c.log.InfoContext(ctx, "gateway.renewed", slog.String("certificate_id", next.Cert.String()))
	return nil
}
