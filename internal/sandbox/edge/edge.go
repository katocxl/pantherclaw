// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package edge is the containment sandbox's trusted sidecar (G0 M9
// decision 1, ADR-0022): the agent's only route out. The agent reaches it as
// its HTTP(S) proxy over the sandbox's internal network. A request for a
// host mapped to a connection goes to the gateway's face for that
// connection, `/{connection}/…`, signed with PAP/1 by the run's workload
// key, which only the edge holds (HR-213); a CONNECT to a mapped host is
// intercepted with a certificate from the per-session CA, whose key exists
// only in the edge's memory. Every other destination, CONNECT or plain, is
// refused and recorded (HR-214). A raw `curl https://api.github.com/…` from
// the agent therefore reaches the same action and decision as the MCP route
// (F099), and nothing else leaves the sandbox.
package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Limits of one proxied request, matching the gateway's HTTP face.
const (
	MaxBody     = 64 << 10
	maxResponse = 16 << 20
	// requestTimeout bounds one request to the gateway (a HOLD answers at
	// once with its wait handle).
	requestTimeout = 2 * time.Minute
	idleTimeout    = 2 * time.Minute
)

// PAP/1 request headers the edge sets for the agent (PAP-1 §4, §5).
const (
	headerRunID    = "PAP-Run-Id"
	headerActionID = "PC-Action-Id"
)

// Route maps a host the agent calls to the gateway connection that serves
// it.
type Route struct {
	// Host is a lowercase DNS name, for example "api.github.com".
	Host       string `json:"host"`
	Connection string `json:"connection"`
}

// Options are what the edge runs with.
type Options struct {
	// GatewayURL is the gateway's public URL: proofs are signed for it
	// (PAP-1 §4).
	GatewayURL string
	// GatewayAddr, when set, is the host:port dialed for GatewayURL, for
	// example host.docker.internal:8090 for a gateway on the host's
	// loopback.
	GatewayAddr string
	// GatewayRoots verifies an HTTPS gateway; nil uses the system roots.
	GatewayRoots *x509.CertPool
	Routes       []Route
	// Run is the run every request names.
	Run string
	// Key is the run's workload key; Token returns its current workload
	// token, "" when there is none.
	Key   ed25519.PrivateKey
	Token func() string
	// CAValidity is how long the session CA and its certificates are
	// valid; 24 h when zero.
	CAValidity time.Duration
	Log        *slog.Logger
}

// Edge is one session's sidecar.
type Edge struct {
	gateway string
	routes  map[string]string
	run     string
	token   func() string
	client  *http.Client
	ca      *authority
	log     *slog.Logger
	refused atomic.Int64
}

// New returns an edge with a fresh session CA.
func New(o Options) (*Edge, error) {
	u, err := url.Parse(strings.TrimSuffix(o.GatewayURL, "/"))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" {
		return nil, fmt.Errorf("edge: gateway URL %q", o.GatewayURL)
	}
	if _, err := ids.ParseUUID(o.Run); err != nil {
		return nil, errors.New("edge: the run must be a run id")
	}
	if len(o.Key) != ed25519.PrivateKeySize || o.Token == nil {
		return nil, errors.New("edge: a workload key and token source are required")
	}
	routes := map[string]string{}
	var hosts []string
	for _, r := range o.Routes {
		if !validHost(r.Host) || r.Connection == "" || routes[r.Host] != "" {
			return nil, fmt.Errorf("edge: route %q → %q", r.Host, r.Connection)
		}
		routes[r.Host] = r.Connection
		hosts = append(hosts, r.Host)
	}
	if len(routes) == 0 {
		return nil, errors.New("edge: no routes")
	}
	validity := o.CAValidity
	if validity <= 0 {
		validity = 24 * time.Hour
	}
	ca, err := newAuthority(hosts, validity, time.Now())
	if err != nil {
		return nil, err
	}
	log := o.Log
	if log == nil {
		log = pclog.Discard()
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	base := &http.Transport{
		Proxy: nil, // the edge never takes a proxy from its environment (HR-072)
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if o.GatewayAddr != "" {
				addr = o.GatewayAddr // this transport only ever reaches the gateway
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: o.GatewayRoots},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Edge{
		gateway: u.String(), routes: routes, run: o.Run, token: o.Token, ca: ca, log: log,
		client: &http.Client{
			Transport: &workloadclient.Transport{Key: o.Key, Token: o.Token, Base: base},
			Timeout:   requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // HR-070
			},
		},
	}, nil
}

// CACertificate is the session CA's certificate (PEM), which the agent
// trusts; its key never leaves the edge (HR-213).
func (e *Edge) CACertificate() []byte { return e.ca.pem }

// CAFingerprint is the SHA-256 of the CA certificate, recorded as the
// session's evidence.
func (e *Edge) CAFingerprint() string { return e.ca.fingerprint }

// Refused counts the requests the edge refused.
func (e *Edge) Refused() int64 { return e.refused.Load() }

// ServeHTTP serves the agent's proxy requests: CONNECT, or a request in
// absolute form for plain HTTP.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		e.connect(w, r)
		return
	}
	if !r.URL.IsAbs() || r.URL.Scheme != "http" {
		e.refuse(w, r, r.Host, http.StatusBadRequest, "not_a_proxy_request")
		return
	}
	host, conn, ok := e.route(r.URL.Host, "80")
	if !ok {
		e.refuse(w, r, r.URL.Host, http.StatusForbidden, "unmapped_destination")
		return
	}
	e.forward(w, r, host, conn)
}

// route returns the host and connection of an authority on the scheme's
// default port, which is the only one mapped.
func (e *Edge) route(authority, port string) (host, conn string, ok bool) {
	h, p, err := net.SplitHostPort(authority)
	if err != nil {
		h, p = authority, port
	}
	h = strings.ToLower(h)
	if p != port {
		return h, "", false
	}
	conn, ok = e.routes[h]
	return h, conn, ok
}

// Refusal is the JSON body of the edge's refusals, in the shape of the
// gateway's own (F642).
type Refusal struct {
	ErrorClass string `json:"error_class"`
	Error      string `json:"error"`
}

// HeaderRefusedBy marks the edge's own refusals, so that a probe tells a
// request that never left the sandbox from the gateway's answer.
const HeaderRefusedBy = "PC-Refused-By"

// refuse answers and records a refused request (HR-214).
func (e *Edge) refuse(w http.ResponseWriter, r *http.Request, dest string, status int, code string) {
	e.refused.Add(1)
	e.log.WarnContext(r.Context(), "edge.refused", "method", r.Method, "destination", dest, "code", code)
	w.Header().Set(HeaderRefusedBy, "edge")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, Refusal{ErrorClass: "CANNOT_AUTHORIZE", Error: code})
}

// connect intercepts a CONNECT to a mapped host with a certificate from the
// session CA and serves the HTTP/1.1 requests inside it.
func (e *Edge) connect(w http.ResponseWriter, r *http.Request) {
	host, conn, ok := e.route(r.Host, "443")
	if !ok {
		e.refuse(w, r, r.Host, http.StatusForbidden, "unmapped_destination")
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		e.refuse(w, r, r.Host, http.StatusInternalServerError, "no_hijack")
		return
	}
	raw, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	if rw.Reader.Buffered() > 0 {
		// The client spoke before the tunnel was open.
		_ = raw.Close()
		return
	}
	if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		_ = raw.Close()
		return
	}
	tc := tls.Server(raw, &tls.Config{
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if hello.ServerName != "" && !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("the server name differs from the CONNECT host")
			}
			return e.ca.leaf(host)
		},
	})
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, in *http.Request) {
			if h, _, ok := e.route(in.Host, "443"); !ok || h != host {
				e.refuse(w, in, in.Host, http.StatusMisdirectedRequest, "host_differs_from_connect")
				return
			}
			e.forward(w, in, host, conn)
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	_ = srv.Serve(newOneConn(tc))
}

// forward sends one request to the gateway's face for its connection and
// answers with the gateway's answer. Only the method, the path and query,
// the body and its Content-Type go on: the agent's own headers, its
// Authorization above all, never leave the sandbox.
func (e *Edge) forward(w http.ResponseWriter, r *http.Request, host, conn string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		e.refuse(w, r, host, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if e.token() == "" {
		e.refuse(w, r, host, http.StatusServiceUnavailable, "edge_has_no_workload_token")
		return
	}
	target := e.gateway + "/" + url.PathEscape(conn) + r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body)) //nolint:gosec // G704: scheme and host are the configured gateway's; the agent supplies only the path and query
	if err != nil {
		e.refuse(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		out.Header.Set("Content-Type", ct)
	}
	action := ids.NewV7().String()
	if a, err := ids.ParseUUID(r.Header.Get(headerActionID)); err == nil {
		action = a.String() // the agent's own retry keeps its action
	}
	out.Header.Set(headerRunID, e.run)
	out.Header.Set(headerActionID, action)
	res, err := e.client.Do(out) //nolint:gosec // G704: only the configured gateway (see above)
	if err != nil {
		e.log.WarnContext(r.Context(), "edge.gateway_unreachable", "connection", conn, "error", err.Error())
		e.refuse(w, r, host, http.StatusBadGateway, "gateway_unreachable")
		return
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(b) > maxResponse {
		e.refuse(w, r, host, http.StatusBadGateway, "gateway_answer_too_large")
		return
	}
	for k, vs := range res.Header {
		if (k == "Content-Type" || k == "Cache-Control" || strings.HasPrefix(k, "Pc-")) && k != http.CanonicalHeaderKey(HeaderRefusedBy) {
			w.Header()[k] = vs
		}
	}
	e.log.InfoContext(r.Context(), "edge.forwarded", "method", r.Method, "connection", conn, "action", action, "status", res.StatusCode)
	w.WriteHeader(res.StatusCode)
	_, _ = w.Write(b)
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ToLower(h) != h || net.ParseIP(h) != nil {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 || strings.Trim(label, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

// oneConn is a listener that yields one connection and then waits until it
// closes, so that an http.Server serves exactly the intercepted tunnel.
type oneConn struct {
	mu   sync.Mutex
	conn net.Conn
	done chan struct{}
}

func newOneConn(c net.Conn) *oneConn {
	l := &oneConn{done: make(chan struct{})}
	l.conn = &closeNotify{Conn: c, once: &sync.Once{}, done: l.done}
	return l
}

func (l *oneConn) Accept() (net.Conn, error) {
	l.mu.Lock()
	c := l.conn
	l.conn = nil
	l.mu.Unlock()
	if c != nil {
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

func (l *oneConn) Close() error   { return nil }
func (l *oneConn) Addr() net.Addr { return &net.TCPAddr{} }

type closeNotify struct {
	net.Conn
	once *sync.Once
	done chan struct{}
}

func (c *closeNotify) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
