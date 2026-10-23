// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net/http"
	"time"
)

// ControlConfig configures a control-plane client.
type ControlConfig struct {
	// Timeout bounds a whole request; default 5 s.
	Timeout time.Duration
	// RootCAs overrides the system roots (private CAs, tests).
	RootCAs *x509.CertPool
	// Wrap decorates the transport, for example to add credentials.
	Wrap func(http.RoundTripper) http.RoundTripper
	// ClientCertificate presents a client certificate (the gateway's mTLS
	// identity, HR-181). With it the client is one end of a link between
	// PantherClaw components: TLS 1.3 and a hybrid post-quantum key
	// exchange only (ComponentLinkTLS, HR-395). Egress clients never carry
	// one (HR-074).
	ClientCertificate func(*tls.CertificateRequestInfo) (*tls.Certificate, error)
	// Link names the component link in the tls.link log line; Log receives
	// it (nil: not logged). Used only with ClientCertificate.
	Link string
	Log  *slog.Logger
}

// NewControlClient returns the client for PantherClaw's own control plane
// (gateway → Authority, JWKS). It never follows redirects (HR-070) and
// ignores proxy environment variables (HR-072). Its transport is separate
// from every egress transport (HR-074). It has no destination deny list,
// because the control plane usually sits on a private address, so it must
// only ever be pointed at configured control-plane URLs, never at targets.
func NewControlClient(cfg ControlConfig) *http.Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.RootCAs != nil {
		tlsConf.RootCAs = cfg.RootCAs
	}
	if cfg.ClientCertificate != nil {
		tlsConf.GetClientCertificate = cfg.ClientCertificate
		ComponentLinkTLS(tlsConf, cfg.Link, cfg.Log)
	}
	var rt http.RoundTripper = &http.Transport{
		Proxy:                 nil, // HR-072
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: timeout,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   256,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	if cfg.Wrap != nil {
		rt = cfg.Wrap(rt)
	}
	return &http.Client{
		Transport: rt,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse // HR-070
		},
	}
}

// StreamingClient returns a copy of base for long-lived streams: the same
// transport (and so the same certificates and dial checks) and the same
// redirect policy, without base's whole-request timeout. A stream ends
// with its context instead.
func StreamingClient(base *http.Client) *http.Client {
	return &http.Client{Transport: base.Transport, CheckRedirect: base.CheckRedirect, Jar: base.Jar}
}
