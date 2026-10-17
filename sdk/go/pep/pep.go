// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Joshua Kato

// Package pep is PantherClaw's reference policy enforcement point for the
// AuthZEN decision endpoint (AuthZEN Authorization API 1.0; PantherClaw
// PN-023). Handler is a reverse proxy placed in front of a target: for
// every request an agent sends it reads the request (at most 64 KiB of
// body), asks PantherClaw whether it may proceed, with the agent's own
// PAP/1 token and proof as the subject, and forwards it unchanged only on
// decision true, adding the action token PantherClaw returns as
// PAP-Action. On decision false it answers 403 with PantherClaw's reason;
// when PantherClaw cannot be asked, 503. It never decides anything itself
// and fails closed.
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
	"net/http"
	"net/http/httputil"
	"net/url"
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

// Config configures a Handler.
type Config struct {
	// Server is PantherClaw's public URL.
	Server string
	// Connection is the name of the connection the enforcement point fronts.
	Connection string
	// Protocol is "http" (the default) or "mcp" (a JSON-RPC MCP server).
	Protocol string
	// PublicURL is the connection's base URL: where agents send their
	// requests, and so the URL their proofs name.
	PublicURL string
	// Upstream is where allowed requests go: the target itself.
	Upstream string
	// Tokens are the enforcement point's access tokens.
	Tokens TokenSource
	// CredentialHeader, when set, is the request header carrying the agent's
	// own target credential (an agent_held connection): it is forwarded as
	// Authorization, which carries the agent's PAP/1 token here.
	CredentialHeader string
	// HTTPClient asks PantherClaw; nil is a client with a 10 second timeout.
	HTTPClient *http.Client
	// Transport sends allowed requests upstream; nil is the default.
	Transport http.RoundTripper
}

// Handler is the enforcement point.
type Handler struct {
	cfg      Config
	public   *url.URL
	eval     string
	client   *http.Client
	upstream *httputil.ReverseProxy
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
	if err != nil || public.Host == "" || (public.Scheme != "https" && public.Scheme != "http") {
		return nil, errors.New("pep: PublicURL must be an http(s) URL")
	}
	up, err := url.Parse(cfg.Upstream)
	if err != nil || up.Host == "" {
		return nil, errors.New("pep: Upstream must be a URL")
	}
	server, err := url.Parse(strings.TrimSuffix(cfg.Server, "/"))
	if err != nil || server.Host == "" {
		return nil, errors.New("pep: Server must be a URL")
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(up)
			pr.Out.Host = up.Host
		},
		Transport: cfg.Transport,
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
		},
	}
	return &Handler{cfg: cfg, public: public, eval: server.String() + EvaluationPath, client: client, upstream: rp}, nil
}

// Decision is PantherClaw's answer about one request.
type Decision struct {
	Decision bool `json:"decision"`
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

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// ServeHTTP asks about one request and forwards it only if allowed.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	if !d.Decision {
		out := refusal{Outcome: pc.Outcome, Code: pc.Code, Reason: d.Context.ReasonUser["en"], TransactionID: pc.TransactionID, ActionID: pc.ActionID}
		if pc.Wait != nil {
			out.WaitHandle, out.WaitDeadline = pc.Wait.Handle, pc.Wait.Deadline
		}
		reply(w, http.StatusForbidden, out)
		return
	}
	out := r.Clone(r.Context())
	out.Body, out.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	for _, k := range []string{"Authorization", HeaderProof, HeaderRunID, HeaderActionID, HeaderAction} {
		out.Header.Del(k)
	}
	if h.cfg.CredentialHeader != "" {
		if v := r.Header.Get(h.cfg.CredentialHeader); v != "" {
			out.Header.Set("Authorization", v)
		}
		out.Header.Del(h.cfg.CredentialHeader)
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

// Ask asks PantherClaw about a request with this body; an error means it
// could not be asked, which the enforcement point treats as a refusal.
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
	ev.Resource = entity{Type: "pantherclaw:http_request", ID: h.cfg.Connection, Properties: map[string]string{
		"protocol": h.cfg.Protocol, "method": r.Method, "url": target.String(), "body_b64": base64.StdEncoding.EncodeToString(body),
	}}
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
	bearer, err := h.cfg.Tokens.Token(ctx)
	if err != nil {
		return Decision{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.eval, bytes.NewReader(raw))
	if err != nil {
		return Decision{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	if id := r.Header.Get("X-Request-ID"); id != "" {
		req.Header.Set("X-Request-ID", id)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return Decision{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, errors.New("pep: the decision endpoint answered " + resp.Status)
	}
	var d Decision
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&d); err != nil {
		return Decision{}, err
	}
	return d, nil
}
