// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/assertion"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/enforcementpoints"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The AuthZEN fixtures (G0 M14 D26-D29): an enforcement point registered
// for the seeded payments connection, its service account's key and
// access token, and the evaluations it sends with the agent's own PAP/1
// credentials.

// azPoint is a registered, ACTIVE enforcement point.
type azPoint struct {
	s        *stack
	id       ids.UUID
	sa       ids.UUID
	clientID string
	kid      string
	priv     ed25519.PrivateKey
	// token is the point's access token; nonce the last PAP/1 nonce it saw.
	token string
	nonce string
	// base is the connection's base URL, which agents sign.
	base  string
	admin person
}

// authzenPoint makes the seeded payments connection access, with base as
// its base URL, and registers and activates an enforcement point for it.
func authzenPoint(t *testing.T, s *stack, access, base string) *azPoint {
	t.Helper()
	admin := s.person(t, "ep-admin", td.RoleOrgAdmin)
	s.db.AdminExec(t, "UPDATE pc.connections SET access_mode = $3, base_url = $4 WHERE org_id = $1 AND id = $2", s.org, s.conn, access, base)
	sas := tapp.NewServiceAccounts(s.pool, credential.EnvTest)
	sa, err := sas.Create(admin.ctx, "edge-pep", "the payments enforcement point")
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwk, _ := jose.JSONWebKey{Key: pub}.MarshalJSON()
	k, err := sas.AddKey(admin.ctx, sa.ID, assertion.EdDSA, string(jwk), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := tapp.NewAccess(s.pool, nil).CreateRoleBinding(admin.ctx, td.RoleEnforcementPoint,
		td.PrincipalRef{Kind: td.KindServiceAccount, ID: sa.ID.UUID()}, td.Scope{Type: td.ScopeOrg, ID: s.org.UUID()}); err != nil {
		t.Fatal(err)
	}
	points := enforcementpoints.New(s.pool)
	pt, err := points.Create(admin.ctx, enforcementpoints.NewPoint{Name: "edge-pep", ServiceAccount: sa.ID.UUID(), Connections: []ids.UUID{s.conn}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := points.Activate(admin.ctx, pt.ID, &stepup.StepUp{Credential: admin.key, At: time.Now()}); err != nil {
		t.Fatal(err)
	}
	p := &azPoint{s: s, id: pt.ID, sa: sa.ID.UUID(), clientID: sa.ClientID, kid: k.KID, priv: priv, base: strings.TrimSuffix(base, "/"), admin: admin}
	p.token = p.accessToken(t)
	return p
}

// accessToken gets an access token with a client assertion (RFC 7523).
func (p *azPoint) accessToken(t *testing.T) string {
	t.Helper()
	claims, _ := json.Marshal(map[string]any{
		"iss": p.clientID, "sub": p.clientID, "aud": p.s.apiURL + authnapp.TokenPath, "jti": ids.NewV7().String(),
		"iat": time.Now().Unix(), "exp": time.Now().Add(2 * time.Minute).Unix(),
	})
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: p.priv}, (&jose.SignerOptions{}).WithHeader("kid", p.kid).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	obj, err := sig.Sign(claims)
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := obj.CompactSerialize()
	form := url.Values{
		"grant_type": {"client_credentials"}, "client_id": {p.clientID},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {compact},
	}
	resp, err := http.Post(p.s.apiURL+authnapp.TokenPath, "application/x-www-form-urlencoded", strings.NewReader(form.Encode())) //nolint:noctx // a test
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var tr struct {
		AccessToken string `json:"access_token"`
	}
	b, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(b, &tr, json.RejectUnknownMembers(false)); err != nil || resp.StatusCode != http.StatusOK || tr.AccessToken == "" {
		t.Fatalf("token: %d %s", resp.StatusCode, b)
	}
	return tr.AccessToken
}

// azAnswer is a decision as the endpoint answers it.
type azAnswer struct {
	Decision bool `json:"decision"`
	Context  struct {
		PantherClaw struct {
			Outcome       string `json:"outcome"`
			Code          string `json:"code"`
			TransactionID string `json:"transaction_id"`
			ActionID      string `json:"action_id"`
			Receipt       string `json:"receipt"`
			Coverage      string `json:"coverage"`
			ActionToken   string `json:"action_token"`
			Nonce         string `json:"nonce"`
			Wait          *struct {
				Handle string `json:"handle"`
			} `json:"wait"`
		} `json:"pantherclaw"`
		ReasonUser map[string]string `json:"reason_user"`
	} `json:"context"`
}

// azRequest is the agent's request the point asks about.
type azRequest struct {
	Method, Path string
	Body         []byte
	// Action is the action id (zero: none, the server makes one).
	Action ids.UUID
	// Key and Token sign it; zero values are the seeded workload's.
	Key   ed25519.PrivateKey
	Token string
	// Agent is the subject id the point names, if any.
	Agent string
	// ProofURL, when set, is the URL the proof is signed for instead of the
	// request's (a proof for another URL).
	ProofURL string
}

// evaluation is the AuthZEN evaluation for r with a fresh proof.
func (p *azPoint) evaluation(t *testing.T, r azRequest) map[string]any {
	t.Helper()
	if r.Key == nil {
		r.Key, r.Token = p.s.key, p.s.token
	}
	if p.nonce == "" {
		p.nonce = p.liveNonce(t)
	}
	u := p.base + r.Path
	htu, _, _ := strings.Cut(u, "?")
	if r.ProofURL != "" {
		htu = r.ProofURL
	}
	proof, err := pap.NewProof(r.Key, pap.ProofParams{Method: r.Method, URL: htu, Body: r.Body, Token: r.Token, Nonce: p.nonce, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	sub := map[string]any{"pap_token": r.Token, "pap_proof": proof, "pap_run_id": p.s.run}
	if !r.Action.IsZero() {
		sub["pc_action_id"] = r.Action.String()
	}
	subject := map[string]any{"type": "pantherclaw_workload", "properties": sub}
	if r.Agent != "" {
		subject["id"] = r.Agent
	}
	props := map[string]any{"protocol": "http", "method": r.Method, "url": u, "body_b64": base64.StdEncoding.EncodeToString(r.Body)}
	if len(r.Body) > 0 {
		props["content_type"] = "application/json"
	}
	return map[string]any{
		"subject":  subject,
		"resource": map[string]any{"type": "pantherclaw:http_request", "id": "payments", "properties": props},
		"action":   map[string]any{"name": r.Method},
	}
}

// liveNonce is the org's newest PAP/1 nonce still accepted.
func (p *azPoint) liveNonce(t *testing.T) string {
	t.Helper()
	return p.s.row(t, `SELECT nonce FROM pc.dpop_nonces WHERE org_id = $1 AND to_timestamp((minute + 6) * 60) > now()
		ORDER BY minute DESC LIMIT 1`, p.s.org)
}

// post sends a body to an endpoint path with the point's token (bearer
// overrides it; "-" sends none) and returns the status and raw answer.
func (p *azPoint) post(t *testing.T, path string, body any, bearer string) (int, []byte) {
	t.Helper()
	st, _, raw := p.postH(t, path, body, bearer)
	return st, raw
}

// postH is post with the answer's headers.
func (p *azPoint) postH(t *testing.T, path string, body any, bearer string) (int, http.Header, []byte) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, p.s.apiURL+path, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	switch bearer {
	case "":
		req.Header.Set("Authorization", "Bearer "+p.token)
	case "-":
	default:
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, out
}

// evaluate asks about one request and returns the decision.
func (p *azPoint) evaluate(t *testing.T, ev map[string]any) azAnswer {
	t.Helper()
	st, raw := p.post(t, "/access/v1/evaluation", ev, "")
	var a azAnswer
	if err := json.Unmarshal(raw, &a, json.RejectUnknownMembers(false)); err != nil || st != http.StatusOK {
		t.Fatalf("evaluation: %d %s", st, raw)
	}
	if n := a.Context.PantherClaw.Nonce; n != "" {
		p.nonce = n
	}
	return a
}
