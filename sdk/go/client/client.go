// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package client is the PantherClaw workload client (PAP/1): it signs a
// proof over every request, keeps the servers' nonces, renews its workload
// token, asks the gateway's /sdk face to decide tool calls and waits on
// held ones.
//
// It fails closed (HR-200): when PantherClaw cannot decide (unreachable,
// timed out, an error, or an answer it cannot read or check) the result is
// CannotDecide, never Allow.
package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/sdk/go/pap"
)

// Config configures a Client.
type Config struct {
	// Key is the workload key file. Its identifier is required; its server
	// and run are the defaults for Server and RunID.
	Key pap.KeyFile
	// Server is the PantherClaw server's base URL (token issuance, waits).
	Server string
	// Gateway is the base URL of the gateway whose /sdk face decides calls.
	Gateway string
	// RunID is the run the workload acts in.
	RunID string
	// Builtins are the names of the tools the agent SDK has built in (for
	// the Claude Agent SDK: Read, Edit, Bash, …). Only these are sent
	// without a server, and only for them does an observe answer let the
	// call run. Empty: no call is a built-in.
	Builtins []string
	// HTTPClient sends the requests; nil uses a default one. Redirects are
	// never followed, whichever client sends. Keep its Timeout zero: a
	// wait stream lasts minutes.
	HTTPClient *http.Client
	// Timeout bounds one decision or token request (default 15 seconds);
	// a long-poll gets its wait on top. Past it, PantherClaw cannot decide.
	Timeout time.Duration
	// MaxWait bounds a wait on a hold whatever its deadline says (default
	// 15 minutes).
	MaxWait time.Duration
	// StreamIdle is how long the SSE wait stream may stay silent,
	// heartbeats included, before the client falls back to long-polls
	// (default 30 seconds, twice the server's heartbeat).
	StreamIdle time.Duration
	// Now is the clock; nil is time.Now.
	Now func() time.Time
}

// Client is a PAP/1 workload client. It is safe for concurrent use.
type Client struct {
	cfg  Config
	priv ed25519.PrivateKey
	jkt  string
	http *http.Client

	mu     sync.Mutex
	token  string
	expiry time.Time
	nonces map[string]string // origin → latest PAP-Nonce
}

// renewBefore is how long before expiry a workload token is renewed.
const renewBefore = 60 * time.Second

// maxResponse caps a response body read.
const maxResponse = 1 << 20

// New returns a client.
func New(cfg Config) (*Client, error) {
	priv, err := cfg.Key.Key()
	if err != nil {
		return nil, err
	}
	if cfg.Server == "" {
		cfg.Server = cfg.Key.Server
	}
	if cfg.RunID == "" {
		cfg.RunID = cfg.Key.RunID
	}
	cfg.Server, cfg.Gateway = strings.TrimSuffix(cfg.Server, "/"), strings.TrimSuffix(cfg.Gateway, "/")
	switch {
	case cfg.Key.Identifier == "":
		return nil, errors.New("client: the key file has no identifier: enroll the workload first")
	case cfg.Server == "":
		return nil, errors.New("client: the PantherClaw server URL is required")
	case !secure(cfg.Server) || (cfg.Gateway != "" && !secure(cfg.Gateway)):
		return nil, errors.New("client: the server and gateway URLs must use https (http only on a loopback address) and carry no user information")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	if cfg.MaxWait <= 0 {
		cfg.MaxWait = 15 * time.Minute
	}
	if cfg.StreamIdle <= 0 {
		cfg.StreamIdle = 30 * time.Second
	}
	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	// A redirect would resend the body and the proof elsewhere.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	pub, _ := priv.Public().(ed25519.PublicKey)
	return &Client{cfg: cfg, priv: priv, jkt: pap.Thumbprint(pub), http: hc, nonces: map[string]string{}}, nil
}

// secure reports whether a base URL may carry workload tokens and proofs:
// https, or http to a loopback address.
func secure(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" {
		return false
	}
	if u.Scheme == "https" {
		return true
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	return u.Scheme == "http" && (host == "localhost" || (ip != nil && ip.IsLoopback()))
}

// JKT returns the thumbprint of the workload key.
func (c *Client) JKT() string { return c.jkt }

// Token returns a workload token valid for at least another minute,
// renewing it at the server when needed.
func (c *Client) Token(ctx context.Context) (string, error) {
	return c.tokenFor(ctx, false)
}

func (c *Client) tokenFor(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	tok, exp := c.token, c.expiry
	c.mu.Unlock()
	if !force && tok != "" && c.cfg.Now().Add(renewBefore).Before(exp) {
		return tok, nil
	}
	body, err := json.Marshal(map[string]string{"identifier": c.cfg.Key.Identifier})
	if err != nil {
		return "", err
	}
	r, err := c.send(ctx, http.MethodPost, c.cfg.Server+"/pantherclaw.v1.WorkloadService/IssueToken", body, connectHeaders(), true, 0)
	if err != nil {
		return "", err
	}
	if r.status != http.StatusOK {
		return "", fmt.Errorf("client: token issuance: HTTP %d %s", r.status, r.header.Get(pap.HeaderError))
	}
	var out struct {
		Token string `json:"workloadToken"`
	}
	if err := json.Unmarshal(r.body, &out); err != nil {
		return "", fmt.Errorf("client: token issuance: %w", err)
	}
	claims, err := pap.ParseTokenClaims(out.Token)
	if err != nil {
		return "", err
	}
	if claims.Cnf.JKT != c.jkt {
		return "", errors.New("client: the server issued a token for another key")
	}
	c.mu.Lock()
	c.token, c.expiry = out.Token, claims.ExpiresAt()
	c.mu.Unlock()
	return out.Token, nil
}

// The retries a PAP/1 refusal asks for.
const (
	RetryNonce   = "retry_nonce"
	RefreshToken = "refresh_token"
)

// Retry says whether a refusal asks the client to retry once: with the
// fresh nonce it carries (use_nonce), or with a renewed workload token
// (token_expired, invalid_token). It returns "" otherwise.
func Retry(status int, h http.Header) string {
	if status != http.StatusUnauthorized {
		return ""
	}
	//exhaustive:ignore // only these two codes ask for a retry
	switch pap.ErrorCode(h.Get(pap.HeaderError)) {
	case pap.ErrUseNonce:
		if h.Get(pap.HeaderNonce) != "" {
			return RetryNonce
		}
	case pap.ErrTokenExpired, pap.ErrInvalidToken:
		return RefreshToken
	}
	return ""
}

func connectHeaders() http.Header {
	return http.Header{"Content-Type": {"application/json"}, "Connect-Protocol-Version": {"1"}}
}

// reply is a response: its status, headers and body, or for an event
// stream the open body, which the caller reads and closes.
type reply struct {
	status int
	header http.Header
	body   []byte
	stream io.ReadCloser
}

// do sends a request with the workload token, allowing extra time on top
// of the configured timeout. A token_expired or invalid_token refusal
// renews the token and retries once.
func (c *Client) do(ctx context.Context, method, target string, body []byte, h http.Header, extra time.Duration) (reply, error) {
	r, err := c.send(ctx, method, target, body, h, false, extra)
	if err == nil && Retry(r.status, r.header) == RefreshToken {
		if _, err := c.tokenFor(ctx, true); err != nil {
			return reply{}, err
		}
		return c.send(ctx, method, target, body, h, false, extra)
	}
	return r, err
}

// send signs and sends one request, retrying once when the server asks for
// a fresh nonce (use_nonce). keyOnly sends no workload token. A request
// for an event stream has no timeout: the caller reads the stream.
func (c *Client) send(ctx context.Context, method, target string, body []byte, h http.Header, keyOnly bool, extra time.Duration) (reply, error) {
	stream := h.Get("Accept") == "text/event-stream"
	if !stream {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout+extra)
		defer cancel()
	}
	r, err := c.sendOnce(ctx, method, target, body, h, keyOnly, stream)
	if err == nil && Retry(r.status, r.header) == RetryNonce {
		return c.sendOnce(ctx, method, target, body, h, keyOnly, stream)
	}
	return r, err
}

func (c *Client) sendOnce(ctx context.Context, method, target string, body []byte, h http.Header, keyOnly, stream bool) (reply, error) {
	u, err := url.Parse(target)
	if err != nil {
		return reply{}, err
	}
	origin := u.Scheme + "://" + u.Host
	var token string
	if !keyOnly {
		if token, err = c.Token(ctx); err != nil {
			return reply{}, err
		}
	}
	c.mu.Lock()
	nonce := c.nonces[origin]
	c.mu.Unlock()
	proof, err := pap.SignProof(c.priv, pap.ProofParams{Method: method, URL: target, Body: body, Token: token, Nonce: nonce, IssuedAt: c.cfg.Now()})
	if err != nil {
		return reply{}, err
	}
	req, err := http.NewRequestWithContext(ctx, method, target, bytes.NewReader(body))
	if err != nil {
		return reply{}, err
	}
	for k, v := range h {
		req.Header[k] = v
	}
	req.Header.Set(pap.HeaderProof, proof)
	if token != "" {
		req.Header.Set("Authorization", pap.AuthScheme+" "+token)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return reply{}, err
	}
	if n := res.Header.Get(pap.HeaderNonce); n != "" {
		c.mu.Lock()
		c.nonces[origin] = n
		c.mu.Unlock()
	}
	r := reply{status: res.StatusCode, header: res.Header}
	if stream && res.StatusCode == http.StatusOK {
		r.stream = res.Body
		return r, nil
	}
	defer func() { _ = res.Body.Close() }()
	r.body, err = io.ReadAll(io.LimitReader(res.Body, maxResponse))
	return r, err
}
