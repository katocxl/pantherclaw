// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
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
	// Proxy, when set, is the HTTP(S) proxy requests go through, except to
	// loopback hosts. Only pclaw sets it, on an explicit opt-in
	// (PANTHERCLAW_HTTPS_PROXY, G0 M2 follow-up); it is never read from the
	// environment here, and egress clients have no such option (HR-072).
	Proxy *url.URL
}

// NewControlClient returns the client for PantherClaw's own control plane
// (gateway → Authority, JWKS). It never follows redirects (HR-070) and
// ignores proxy environment variables (HR-072): it uses a proxy only when
// cfg.Proxy names one. Its transport is separate
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
	var proxy func(*http.Request) (*url.URL, error) // HR-072: never from the environment
	if cfg.Proxy != nil {
		p := *cfg.Proxy
		proxy = func(r *http.Request) (*url.URL, error) {
			if isLoopbackHost(r.URL.Hostname()) {
				return nil, nil //nolint:nilnil // direct
			}
			return &p, nil
		}
	}
	var rt http.RoundTripper = &http.Transport{
		Proxy:                 proxy,
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

// ParseControlProxy checks an opted-in control-plane proxy URL: http or
// https, with a host and nothing after it.
func ParseControlProxy(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	var ue *url.Error
	switch {
	case errors.As(err, &ue):
		return nil, fmt.Errorf("proxy URL: %w", ue.Err) // never the URL itself: it may hold a password
	case err != nil:
		return nil, errors.New("proxy URL: not a URL")
	case u.Scheme != "http" && u.Scheme != "https":
		return nil, fmt.Errorf("proxy URL %q: the scheme is http or https", u.Redacted())
	case u.Host == "" || u.Hostname() == "":
		return nil, fmt.Errorf("proxy URL %q names no host", u.Redacted())
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "":
		return nil, fmt.Errorf("proxy URL %q: only scheme, host and port", u.Redacted())
	}
	u.Path = ""
	return u, nil
}

// isLoopbackHost reports localhost and loopback addresses.
func isLoopbackHost(h string) bool {
	if strings.EqualFold(h, "localhost") || strings.HasSuffix(strings.ToLower(h), ".localhost") {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsLoopback()
}

// StreamingClient returns a copy of base for long-lived streams: the same
// transport (and so the same certificates and dial checks) and the same
// redirect policy, without base's whole-request timeout. A stream ends
// with its context instead.
func StreamingClient(base *http.Client) *http.Client {
	return &http.Client{Transport: base.Transport, CheckRedirect: base.CheckRedirect, Jar: base.Jar}
}
