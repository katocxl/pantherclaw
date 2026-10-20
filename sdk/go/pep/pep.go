// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package pep is PantherClaw's reference policy enforcement point for the
// AuthZEN decision endpoint (AuthZEN Authorization API 1.0; PantherClaw
// PN-023). Handler is a reverse proxy placed in front of a target: for
// every request an agent sends it reads the request (at most 64 KiB of
// body), asks PantherClaw whether it may proceed, with the agent's own
// PAP/1 token and proof as the subject, and forwards exactly the evaluated
// method, URL, content type and body only on decision true, adding the
// action token PantherClaw returns as PAP-Action. On decision false it
// answers 403 with PantherClaw's reason; when PantherClaw cannot be asked,
// 503. It never decides anything itself and fails closed.
//
// Only an allow-list of request headers reaches the target; a request that
// could mean something else to the target than what was evaluated (an
// encoded body, a method override, trailers) is refused.
//
// The enforcement point authenticates as its registered service account
// (ClientCredentials) and may only ask about the connection it is bound
// to. The agent addresses the enforcement point at the connection's base
// URL (PublicURL), so its proofs name the URL PantherClaw checks.
package pep

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/textproto"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Header names.
const (
	HeaderProof    = "PAP-Proof"
	HeaderRunID    = "PAP-Run-Id"
	HeaderActionID = "PC-Action-Id"
	HeaderAction   = "PAP-Action"
	// HeaderNonce passes PantherClaw's current nonce to the agent.
	HeaderNonce = "PAP-Nonce"
	// HeaderTransaction and HeaderOutcome tell the agent what PantherClaw
	// decided.
	HeaderTransaction = "PC-Transaction-Id"
	HeaderOutcome     = "PC-Outcome"
)

// MaxBody is the largest request body the enforcement point forwards.
const MaxBody = 64 << 10

// EvaluationPath is the decision endpoint's path on the server.
const EvaluationPath = "/access/v1/evaluation"

// DefaultForwardHeaders are the request headers forwarded to the target
// when Config.ForwardHeaders is empty; Content-Type is always forwarded,
// exactly as evaluated.
var DefaultForwardHeaders = []string{"Accept", "Accept-Language", "User-Agent", "X-Request-ID"}

// Config configures a Handler.
type Config struct {
	// Server is PantherClaw's public URL: https, or http to a loopback
	// address unless AllowInsecure.
	Server string
	// Connection is the name of the connection the enforcement point fronts.
	Connection string
	// Protocol is "http" (the default) or "mcp" (a JSON-RPC MCP server).
	Protocol string
	// PublicURL is the connection's base URL: where agents send their
	// requests, and so the URL their proofs name.
	PublicURL string
	// Upstream is where allowed requests go: the target itself, without a
	// query or fragment.
	Upstream string
	// Tokens are the enforcement point's access tokens.
	Tokens TokenSource
	// ForwardHeaders are the request headers, besides Content-Type, that
	// reach the target; empty is DefaultForwardHeaders. PAP-* and PC-*
	// headers can never be listed.
	ForwardHeaders []string
	// CredentialHeader, when set, is the request header carrying the agent's
	// own target credential (an agent_held connection): it is forwarded as
	// Authorization, which carries the agent's PAP/1 token here.
	CredentialHeader string
	// AllowInsecure accepts an http Server that is not a loopback address.
	AllowInsecure bool
	// HTTPClient asks PantherClaw; nil is a client with a 10 second timeout
	// that ignores proxy settings. It never follows redirects.
	HTTPClient *http.Client
	// Transport sends allowed requests upstream; nil is a transport that
	// ignores proxy settings and waits at most 30 seconds for headers.
	Transport http.RoundTripper
	// Log records upstream errors; nil logs nothing.
	Log *slog.Logger
}

// Handler is the enforcement point.
type Handler struct {
	cfg      Config
	public   *url.URL
	eval     string
	client   *http.Client
	forward  []string
	upstream *httputil.ReverseProxy
}

// reserved reports a PAP-* or PC-* header in any spelling.
func reserved(name string) bool {
	n := strings.ToLower(strings.ReplaceAll(name, "_", "-"))
	return strings.HasPrefix(n, "pap-") || strings.HasPrefix(n, "pc-")
}

// loopback reports whether a URL's host is a loopback address or localhost.
func loopback(u *url.URL) bool {
	h := u.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

// transport ignores proxy settings (HR-072) and bounds every phase.
func transport() *http.Transport {
	return &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConnsPerHost:   16,
		ForceAttemptHTTP2:     true,
	}
}

// New returns an enforcement point.
func New(cfg Config) (*Handler, error) {
	if cfg.Protocol == "" {
		cfg.Protocol = "http"
	}
	if cfg.Protocol != "http" && cfg.Protocol != "mcp" {
		return nil, errors.New("pep: protocol must be http or mcp")
	}
	if cfg.Connection == "" || cfg.Tokens == nil {
		return nil, errors.New("pep: a connection and a token source are required")
	}
	public, err := url.Parse(strings.TrimSuffix(cfg.PublicURL, "/"))
	if err != nil || public.Host == "" || (public.Scheme != "https" && public.Scheme != "http") || public.RawQuery != "" || public.Fragment != "" {
		return nil, errors.New("pep: PublicURL must be an http(s) URL without a query")
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Host == "" || (up.Scheme != "https" && up.Scheme != "http") || up.RawQuery != "" || up.ForceQuery || up.Fragment != "" {
		return nil, errors.New("pep: Upstream must be an http(s) URL without a query or fragment")
	}
	server, err := url.Parse(strings.TrimSuffix(cfg.Server, "/"))
	if err != nil || server.Host == "" || (server.Scheme != "https" && server.Scheme != "http") {
		return nil, errors.New("pep: Server must be an http(s) URL")
	}
	if server.Scheme == "http" && !loopback(server) && !cfg.AllowInsecure {
		return nil, errors.New("pep: Server must be https unless it is a loopback address")
	}
	forward := cfg.ForwardHeaders
	if len(forward) == 0 {
		forward = DefaultForwardHeaders
	}
	var canon []string
	for _, f := range forward {
		if f == "" || strings.ContainsAny(f, "_ \t:") || reserved(f) || strings.EqualFold(f, "Authorization") {
			return nil, errors.New("pep: ForwardHeaders cannot name " + f)
		}
		canon = append(canon, textproto.CanonicalMIMEHeaderKey(f))
	}
	log := cfg.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	tr := cfg.Transport
	if tr == nil {
		tr = transport()
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = up.Host
		},
		Transport: tr,
		// The target cannot speak for PantherClaw.
		ModifyResponse: func(res *http.Response) error {
			for k := range res.Header {
				if reserved(k) {
					delete(res.Header, k)
				}
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.WarnContext(r.Context(), "pep.upstream_failed", slog.String("error", err.Error()))
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return &Handler{cfg: cfg, public: public, eval: server.String() + EvaluationPath, client: noRedirects(cfg.HTTPClient), forward: canon, upstream: rp}, nil
}

// Decision is PantherClaw's answer about one request.
type Decision struct {
	// Decision is required: an answer without it is no answer.
	Decision *bool `json:"decision"`
	Context  struct {
		PantherClaw struct {
			Outcome       string `json:"outcome"`
			Code          string `json:"code,omitempty"`
			TransactionID string `json:"transaction_id,omitempty"`
			ActionID      string `json:"action_id,omitempty"`
			Receipt       string `json:"receipt,omitempty"`
			Coverage      string `json:"coverage"`
			Wait          *struct {
				Handle   string `json:"handle"`
				Deadline string `json:"deadline,omitempty"`
			} `json:"wait,omitempty"`
			ActionToken string `json:"action_token,omitempty"`
			Nonce       string `json:"nonce,omitempty"`
		} `json:"pantherclaw"`
		ReasonUser map[string]string `json:"reason_user,omitempty"`
	} `json:"context"`
}

// Allowed reports the decision.
func (d Decision) Allowed() bool { return d.Decision != nil && *d.Decision }

// refusal is the body of a 403.
type refusal struct {
	Decision      bool   `json:"decision"`
	Outcome       string `json:"outcome"`
	Code          string `json:"code,omitempty"`
	Reason        string `json:"reason,omitempty"`
	TransactionID string `json:"transaction_id,omitempty"`
	ActionID      string `json:"action_id,omitempty"`
	WaitHandle    string `json:"wait_handle,omitempty"`
	WaitDeadline  string `json:"wait_deadline,omitempty"`
}

func reply(w http.ResponseWriter, status int, v refusal) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	b, err := json.Marshal(v)
	if err != nil {
		status, b = http.StatusInternalServerError, []byte(`{"decision":false,"outcome":"cannot_authorize"}`)
	}
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// ambiguous reports a request the target could read otherwise than it is
// evaluated: an encoded body, a method override, or trailers.
func ambiguous(r *http.Request) bool {
	if ce := r.Header.Values("Content-Encoding"); len(ce) > 0 && !(len(ce) == 1 && strings.EqualFold(strings.TrimSpace(ce[0]), "identity")) {
		return true
	}
	if len(r.Trailer) > 0 || r.Header.Get("Trailer") != "" {
		return true
	}
	for k := range r.Header {
		if strings.Contains(strings.ToLower(strings.ReplaceAll(k, "_", "-")), "method-override") {
			return true
		}
	}
	return false
}

// ServeHTTP asks about one request and forwards it only if allowed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if ambiguous(r) {
		reply(w, http.StatusBadRequest, refusal{Outcome: "cannot_authorize", Code: "ambiguous_request"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil {
		reply(w, http.StatusBadRequest, refusal{Outcome: "cannot_authorize", Code: "invalid_request"})
		return
	}
	if len(body) > MaxBody {
		reply(w, http.StatusRequestEntityTooLarge, refusal{Outcome: "cannot_authorize", Code: "body_too_large"})
		return
	}
	d, err := h.Ask(r.Context(), r, body)
	if err != nil {
		reply(w, http.StatusServiceUnavailable, refusal{Outcome: "cannot_authorize", Code: "decision_unavailable"})
		return
	}
	pc := d.Context.PantherClaw
	if pc.TransactionID != "" {
		w.Header().Set(HeaderTransaction, pc.TransactionID)
	}
	w.Header().Set(HeaderOutcome, pc.Outcome)
	if pc.Nonce != "" {
		// The agent signs its next proof with it (PAP/1).
		w.Header().Set(HeaderNonce, pc.Nonce)
	}
	if !d.Allowed() {
		out := refusal{Outcome: pc.Outcome, Code: pc.Code, Reason: d.Context.ReasonUser["en"], TransactionID: pc.TransactionID, ActionID: pc.ActionID}
		if pc.Wait != nil {
			out.WaitHandle, out.WaitDeadline = pc.Wait.Handle, pc.Wait.Deadline
		}
		reply(w, http.StatusForbidden, out)
		return
	}
	out := r.Clone(r.Context())
	out.Body, out.ContentLength, out.Trailer = io.NopCloser(bytes.NewReader(body)), int64(len(body)), nil
	out.Header = http.Header{}
	for _, k := range h.forward {
		if v := r.Header.Values(k); len(v) > 0 {
			out.Header[k] = slices.Clone(v)
		}
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		out.Header.Set("Content-Type", ct)
	}
	if h.cfg.CredentialHeader != "" {
		if v := r.Header.Get(h.cfg.CredentialHeader); v != "" {
			out.Header.Set("Authorization", v)
		}
	}
	if pc.ActionToken != "" {
		out.Header.Set(HeaderAction, pc.ActionToken)
	}
	h.upstream.ServeHTTP(w, out)
}

type entity struct {
	Type       string `json:"type"`
	ID         string `json:"id,omitempty"`
	Properties any    `json:"properties,omitempty"`
}

type evaluation struct {
	Subject  entity `json:"subject"`
	Resource entity `json:"resource"`
	Action   struct {
		Name string `json:"name"`
	} `json:"action"`
}

// invalidator is a token source that can drop a token the server refused.
type invalidator interface{ Invalidate() }

// Ask asks PantherClaw about a request with this body; an error means it
// could not be asked, which the enforcement point treats as a refusal. A
// token the decision endpoint refuses is dropped and the question asked
// once more with a new one.
func (h *Handler) Ask(ctx context.Context, r *http.Request, body []byte) (Decision, error) {
	target := *h.public
	target.Path, target.RawPath = h.public.Path+r.URL.Path, ""
	if r.URL.RawPath != "" {
		target.RawPath = h.public.EscapedPath() + r.URL.RawPath
	}
	target.RawQuery = r.URL.RawQuery
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "PAP ")
	sub := map[string]string{"pap_token": token, "pap_proof": r.Header.Get(HeaderProof), "pap_run_id": r.Header.Get(HeaderRunID)}
	if a := r.Header.Get(HeaderActionID); a != "" {
		sub["pc_action_id"] = a
	}
	var ev evaluation
	ev.Subject = entity{Type: "pantherclaw_workload", Properties: sub}
	props := map[string]string{
		"protocol": h.cfg.Protocol, "method": r.Method, "url": target.String(), "body_b64": base64.StdEncoding.EncodeToString(body),
	}
	if ct := r.Header.Get("Content-Type"); ct != "" {
		props["content_type"] = ct
	}
	ev.Resource = entity{Type: "pantherclaw:http_request", ID: h.cfg.Connection, Properties: props}
	ev.Action.Name = r.Method
	if h.cfg.Protocol == "mcp" {
		var m struct {
			Method string `json:"method"`
		}
		_ = json.Unmarshal(body, &m)
		ev.Action.Name = m.Method
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		return Decision{}, err
	}
	for attempt := 0; ; attempt++ {
		d, status, err := h.ask(ctx, r.Header.Get("X-Request-ID"), raw)
		if status == http.StatusUnauthorized && attempt == 0 {
			if inv, ok := h.cfg.Tokens.(invalidator); ok {
				inv.Invalidate()
				continue
			}
		}
		return d, err
	}
}

func (h *Handler) ask(ctx context.Context, requestID string, raw []byte) (Decision, int, error) {
	bearer, err := h.cfg.Tokens.Token(ctx)
	if err != nil {
		return Decision{}, 0, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.eval, bytes.NewReader(raw))
	if err != nil {
		return Decision{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if requestID != "" {
		req.Header.Set("X-Request-ID", requestID)
	}
	resp, err := h.client.Do(req) //nolint:gosec // G704: the operator configures the decision endpoint
	if err != nil {
		return Decision{}, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, resp.StatusCode, errors.New("pep: the decision endpoint answered " + resp.Status)
	}
	var d Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return Decision{}, resp.StatusCode, err
	}
	if d.Decision == nil {
		return Decision{}, resp.StatusCode, errors.New("pep: the answer has no decision")
	}
	return d, resp.StatusCode, nil
}
