// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package edge is the containment sandbox's trusted sidecar, run as
// `pantherclaw-edge` in its own container (G0 M9 decision 1, ADR-0022): the
// agent's only route out. The agent reaches it as its HTTPS proxy over the
// sandbox's internal network. A CONNECT to port 443 of an agent host of a
// mapped connection is intercepted with a certificate from the per-session
// CA, whose key exists only in the edge's memory, and every request inside
// goes to the gateway's HTTP face for that connection, `/{connection}/…`,
// signed with PAP/1 by the run's workload key, which only the edge holds
// (HR-213). Everything else is refused with 403 and recorded: another host
// or port, an IP literal, plain HTTP and WebSocket upgrades (HR-214). The
// edge dials nothing but the gateway, so a raw `curl https://api.github.com/…`
// from the agent reaches the same action and decision as the MCP route
// (F099), and with the gateway down it reaches nothing.
package edge

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/url"
	"slices"
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

// Headers the edge sets on the gateway request (PAP-1 §4, §5; G0 M9 edge
// protocol). PC-Sandbox-Session is informational: the server binds the
// session through the instance.
const (
	headerRunID   = "PAP-Run-Id"
	headerAction  = "PC-Action-Id"
	headerSession = "PC-Sandbox-Session"
	// HeaderRefusedBy marks the edge's own refusals, so that a probe tells
	// a request that never left the sandbox from the gateway's answer.
	HeaderRefusedBy = "PC-Refused-By"
)

// credentialHeaders carry a credential the agent may have found: the edge
// strips them all and reports each (G0 M9 design decision 11).
var credentialHeaders = []string{"Authorization", "Cookie", "X-Api-Key", "Api-Key", "Private-Token", "X-Auth-Token"}

// Options are what the edge runs with.
type Options struct {
	// Session is the sandbox session, sent as PC-Sandbox-Session.
	Session string
	// GatewayURL is the gateway's public URL: proofs are signed for it
	// (PAP-1 §4).
	GatewayURL string
	// GatewayAddr, when set, is the host:port dialed for GatewayURL, for
	// example host.docker.internal:8090 for a gateway on the host's
	// loopback.
	GatewayAddr string
	// GatewayCAPin ("sha256:<hex>") pins the CA of an HTTPS gateway; empty
	// uses the system roots.
	GatewayCAPin string
	// Hosts maps each agent host (a lowercase DNS name) to the connection
	// that serves it.
	Hosts map[string]string
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
	session, gateway, run string
	hosts                 map[string]string
	token                 func() string
	client                *http.Client
	ca                    *authority
	log                   *slog.Logger
	refused, stripped     atomic.Int64
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
	if len(o.Hosts) == 0 || len(o.Hosts) > 64 {
		return nil, errors.New("edge: 1 to 64 agent hosts")
	}
	for h, c := range o.Hosts {
		if !validHost(h) || c == "" || strings.ContainsAny(c, "/?#%") {
			return nil, fmt.Errorf("edge: host %q → %q", h, c)
		}
	}
	tlsConf, err := gatewayTLS(o.GatewayCAPin)
	if err != nil {
		return nil, err
	}
	validity := o.CAValidity
	if validity <= 0 {
		validity = 24 * time.Hour
	}
	ca, err := newAuthority(slices.Sorted(maps.Keys(o.Hosts)), validity, time.Now)
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
				addr = o.GatewayAddr // this transport only ever reaches the gateway (HR-213)
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: requestTimeout,
		IdleConnTimeout:       90 * time.Second,
		ForceAttemptHTTP2:     true,
	}
	return &Edge{
		session: o.Session, gateway: u.String(), run: o.Run, hosts: maps.Clone(o.Hosts), token: o.Token, ca: ca, log: log,
		client: &http.Client{
			Transport: &workloadclient.Transport{Key: o.Key, Token: o.Token, Base: base},
			Timeout:   requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse // HR-070
			},
		},
	}, nil
}

// gatewayTLS verifies an HTTPS gateway against the system roots, or, with
// a pin, against the pinned CA in the chain it presents.
func gatewayTLS(pin string) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin == "" {
		return c, nil
	}
	want, ok := strings.CutPrefix(pin, "sha256:")
	if b, err := hex.DecodeString(want); !ok || err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("edge: gateway CA pin %q is not sha256:<hex>", pin)
	}
	// The pin replaces the system roots: VerifyConnection checks the chain.
	c.InsecureSkipVerify = true
	c.VerifyConnection = func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			return errors.New("edge: the gateway presented no certificate")
		}
		// The pinned certificate may be any in the chain the gateway
		// presents, its leaf included (a self-signed gateway).
		roots, inter := x509.NewCertPool(), x509.NewCertPool()
		var pinned bool
		for i, cert := range cs.PeerCertificates {
			sum := sha256.Sum256(cert.Raw)
			switch {
			case hex.EncodeToString(sum[:]) == want:
				roots.AddCert(cert)
				pinned = true
			case i > 0:
				inter.AddCert(cert)
			}
		}
		if !pinned {
			return errors.New("edge: the gateway's chain lacks the pinned CA")
		}
		_, err := cs.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, DNSName: cs.ServerName})
		return err
	}
	return c, nil
}

// CACertificate is the session CA's certificate (PEM), which the agent
// trusts; its key never leaves the edge (HR-213).
func (e *Edge) CACertificate() []byte { return e.ca.pem }

// CAFingerprint is the SHA-256 of the CA certificate, recorded as the
// session's evidence.
func (e *Edge) CAFingerprint() string { return e.ca.fingerprint }

// Refused counts the requests the edge refused, Stripped the credentials
// it removed from requests.
func (e *Edge) Refused() int64  { return e.refused.Load() }
func (e *Edge) Stripped() int64 { return e.stripped.Load() }

// ServeHTTP serves the agent's proxy requests. Only a CONNECT to port 443
// of an agent host is served; everything else is refused.
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		dest := r.Host
		if r.URL.IsAbs() {
			dest = r.URL.Host
		}
		e.refuse(w, r, dest, "plain_http_refused")
		return
	}
	host, conn, ok := e.route(r.Host)
	if !ok {
		e.refuse(w, r, r.Host, "unmapped_destination")
		return
	}
	e.tunnel(w, r, host, conn)
}

// route returns the host and connection of a CONNECT authority, which must
// be an agent host on port 443.
func (e *Edge) route(authority string) (host, conn string, ok bool) {
	h, p, err := net.SplitHostPort(authority)
	if err != nil || p != "443" {
		return "", "", false
	}
	h = strings.ToLower(h)
	conn, ok = e.hosts[h]
	return h, conn, ok
}

// Refusal is the JSON body of the edge's refusals, in the shape of the
// gateway's own (F642).
type Refusal struct {
	ErrorClass string `json:"error_class"`
	Error      string `json:"error"`
}

// refuse answers 403 and records a refused request (HR-214): its method
// and destination, which the session reports as an observed direct_api
// route.
func (e *Edge) refuse(w http.ResponseWriter, r *http.Request, dest, code string) {
	e.answer(w, r, dest, http.StatusForbidden, code)
}

func (e *Edge) answer(w http.ResponseWriter, r *http.Request, dest string, status int, code string) {
	e.refused.Add(1)
	e.log.WarnContext(r.Context(), "edge.refused", "method", r.Method, "destination", bounded(dest), "code", code)
	w.Header().Set(HeaderRefusedBy, "edge")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, Refusal{ErrorClass: "CANNOT_AUTHORIZE", Error: code})
}

func bounded(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return strings.ToValidUTF8(s, "?")
}

// tunnel intercepts a CONNECT to an agent host with a certificate from the
// session CA and serves the HTTP/1.1 requests inside it.
func (e *Edge) tunnel(w http.ResponseWriter, r *http.Request, host, conn string) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		e.answer(w, r, r.Host, http.StatusInternalServerError, "no_hijack")
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
			switch h, _, err := net.SplitHostPort(in.Host); {
			case !strings.EqualFold(in.Host, host) && (err != nil || !strings.EqualFold(h, host)):
				e.answer(w, in, in.Host, http.StatusMisdirectedRequest, "host_differs_from_connect")
			case in.Header.Get("Upgrade") != "" || strings.Contains(strings.ToLower(in.Header.Get("Connection")), "upgrade"):
				e.refuse(w, in, host, "upgrade_refused")
			default:
				e.forward(w, in, host, conn)
			}
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    32 << 10,
		ErrorLog:          slog.NewLogLogger(e.log.Handler(), slog.LevelWarn),
	}
	_ = srv.Serve(newOneConn(tc))
}

// forward sends one request to the gateway's face for its connection and
// answers with the gateway's answer, never retrying on its own. Only the
// method, the path and query, the body, Content-Type and Accept go on:
// credentials in headers or in the query, cookies, proxy and forwarding
// headers never leave the sandbox, and each credential stripped is
// reported.
func (e *Edge) forward(w http.ResponseWriter, r *http.Request, host, conn string) {
	e.strip(r, host)
	query := e.stripQuery(r, host)
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		e.answer(w, r, host, http.StatusRequestEntityTooLarge, "body_too_large")
		return
	}
	if e.token() == "" {
		e.answer(w, r, host, http.StatusServiceUnavailable, "edge_has_no_workload_token")
		return
	}
	target := e.gateway + "/" + url.PathEscape(conn) + r.URL.EscapedPath()
	if query != "" {
		target += "?" + query
	}
	ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
	defer cancel()
	out, err := http.NewRequestWithContext(ctx, r.Method, target, bytes.NewReader(body)) //nolint:gosec // G704: scheme and host are the configured gateway's; the agent supplies only the path and query
	if err != nil {
		e.answer(w, r, host, http.StatusBadRequest, "invalid_request")
		return
	}
	for _, h := range []string{"Content-Type", "Accept"} {
		if v := r.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	action := ids.NewV7().String()
	out.Header.Set(headerRunID, e.run)
	out.Header.Set(headerAction, action)
	if e.session != "" {
		out.Header.Set(headerSession, e.session)
	}
	res, err := e.client.Do(out) //nolint:gosec // G704: only the configured gateway (see above)
	if err != nil {
		e.log.WarnContext(r.Context(), "edge.gateway_unreachable", "connection", conn, "error", err.Error())
		e.answer(w, r, host, http.StatusBadGateway, "gateway_unreachable")
		return
	}
	defer func() { _ = res.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(res.Body, maxResponse+1))
	if err != nil || len(b) > maxResponse {
		e.answer(w, r, host, http.StatusBadGateway, "gateway_answer_too_large")
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

// strip reports every credential header of a request: its name, kind and
// a SHA-256 prefix, never the value. None of them is forwarded anyway.
func (e *Edge) strip(r *http.Request, host string) {
	for _, h := range credentialHeaders {
		for _, v := range r.Header.Values(h) {
			e.stripped.Add(1)
			sum := sha256.Sum256([]byte(v))
			e.log.WarnContext(r.Context(), "edge.credential_stripped", "header", h, "kind", credentialKind(h, v),
				"sha256_prefix", hex.EncodeToString(sum[:6]), "destination", host)
		}
	}
}

// credentialParams are query parameters that carry a credential.
var credentialParams = []string{"access_token", "auth_token", "token", "api_key", "apikey", "private_token", "client_secret", "password"}

// stripQuery returns the request's query without the parameters that carry
// a credential, by name or by a well-known prefix, and reports each like a
// header (G0 M9 design decision 11). The other parameters keep their order
// and encoding.
func (e *Edge) stripQuery(r *http.Request, host string) string {
	if r.URL.RawQuery == "" {
		return ""
	}
	var kept []string
	for _, p := range strings.Split(r.URL.RawQuery, "&") {
		k, v, _ := strings.Cut(p, "=")
		name, err1 := url.QueryUnescape(k)
		value, err2 := url.QueryUnescape(v)
		if err1 != nil || err2 != nil {
			name, value = k, v
		}
		kind := tokenKind(value)
		if kind == "" && !slices.Contains(credentialParams, strings.ToLower(name)) {
			kept = append(kept, p)
			continue
		}
		if kind == "" {
			kind = "query:" + strings.ToLower(bounded(name))
		}
		e.stripped.Add(1)
		sum := sha256.Sum256([]byte(value))
		e.log.WarnContext(r.Context(), "edge.credential_stripped", "query", bounded(name), "kind", kind,
			"sha256_prefix", hex.EncodeToString(sum[:6]), "destination", host)
	}
	return strings.Join(kept, "&")
}

// credentialKind names what a credential looks like, from its scheme and
// well-known prefixes.
func credentialKind(header, v string) string {
	scheme, token, found := strings.Cut(strings.TrimSpace(v), " ")
	if !found {
		scheme, token = "", scheme
	}
	if k := tokenKind(token); k != "" {
		return k
	}
	if scheme != "" {
		return strings.ToLower(header) + ":" + strings.ToLower(scheme)
	}
	return strings.ToLower(header)
}

// tokenKind names a token by its well-known prefix, "" when it has none.
func tokenKind(token string) string {
	for _, p := range []struct{ prefix, kind string }{
		{"github_pat_", "github_pat"},
		{"ghp_", "github_pat"},
		{"gho_", "github_oauth"},
		{"ghu_", "github_user"},
		{"ghs_", "github_installation"},
		{"ghr_", "github_refresh"},
		{"glpat-", "gitlab_pat"},
		{"sk_live_", "stripe_live"},
		{"xoxb-", "slack_bot"},
		{"AKIA", "aws_access_key"},
	} {
		if strings.HasPrefix(token, p.prefix) {
			return p.kind
		}
	}
	return ""
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
