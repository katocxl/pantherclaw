// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gateway"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/grants/grantstest"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idjag"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	idapp "github.com/katocxl/pantherclaw/internal/idaccess/app"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/idaccess/ports"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	"github.com/katocxl/pantherclaw/internal/sim/okta"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// IdP-native agent access on a running stack (G0 M26 D400-D403, D408). The
// org trusts a simulated Okta as an assertion issuer, binds an Okta client
// to the seeded agent and turns MCP authorization on for the stack's
// gateway. A person of the simulated IdP holds a grant of the seeded agent
// like the seeded owner's.
//
// The token endpoint's use cases run in the test, against the stack's
// database and signing with the server's own mcp_tokens key: the server's
// egress guard refuses the loopback simulator, as it must (HR-071), and a
// dev seam to let it through would be one more thing to keep out of
// production. Every call with the token goes through the running gateway
// and Authority.

const (
	idpClientID   = "0oa-e2e-coder"
	idpPerson     = "00u-alice"
	idpNobody     = "00u-nogrant"
	idpConnection = "payments"
	idpMcpClient  = "https://editor.example/oauth/client.json"
	idpRedirect   = "http://127.0.0.1:4567/callback"
	idpVerifier   = "e2e-pkce-verifier-0123456789-abcdefghijklmnopqrstuvwxyz"
)

// idpAccess is the stack with IdP-native access set up.
type idpAccess struct {
	s        *stack
	sim      *okta.Sim
	ex       *idapp.Exchange
	flow     *idapp.CodeFlow
	agent    ids.UUID
	instance ids.UUID
	kid      string
	person   ids.UUID
	grant    gdomain.GrantID
	binding  ids.UUID
	client   ids.UUID
	resource string
}

// idpDocs is the allow-listed client's metadata document.
type idpDocs map[string]ports.ClientMetadata

func (d idpDocs) Fetch(_ context.Context, u string) (ports.ClientMetadata, error) {
	md, ok := d[u]
	if !ok {
		return ports.ClientMetadata{}, errors.New("unreachable")
	}
	return md, nil
}

// idpAccessOn sets IdP-native access up on s and waits until the gateway
// serves the org's OAuth route.
func (s *stack) idpAccessOn(t *testing.T) *idpAccess {
	t.Helper()
	ctx := context.Background()
	var h http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	sim, err := okta.New(srv.URL, okta.Faults{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h = sim.Handler()
	a := &idpAccess{
		s: s, sim: sim, person: ids.NewV7(), binding: ids.NewV7(), client: ids.NewV7(),
		resource: iddomain.ResourceURL(s.gateway, idpConnection),
	}

	var seeded string
	var owner ids.UUID
	s.query(t, `SELECT r.agent_id, r.grant_id::text, ag.owner_user_id FROM pc.runs r
		JOIN pc.agents ag ON ag.org_id = r.org_id AND ag.id = r.agent_id WHERE r.id = $1`, []any{s.run}, &a.agent, &seeded, &owner)
	a.kid = thumbprint(t, s.key.Public().(ed25519.PublicKey))
	s.query(t, "SELECT id FROM pc.agent_instances WHERE agent_id = $1 AND jkt = $2", []any{a.agent, a.kid}, &a.instance)

	// The person, with a grant like the owner's.
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", s.org, a.person, sim.Issuer(), idpPerson)
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", s.org, ids.NewV7(), sim.Issuer(), idpNobody)
	store := &grantspg.Store{Pool: s.pool}
	sid, err := gdomain.ParseGrantID(seeded)
	if err != nil {
		t.Fatal(err)
	}
	g, err := store.Grant(ctx, s.org, sid)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	g.ID, g.Revision, g.State = gdomain.NewGrantID(), 1, gdomain.StateActive
	g.Principal = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: a.person}
	g.Grantor = gdomain.Principal{Kind: gdomain.PrincipalUser, ID: owner}
	g.NotBefore, g.ExpiresAt, g.Basis, g.TaskRef = now.Add(-time.Minute), now.Add(24*time.Hour), "e2e: the IdP person's grant", "e2e"
	if err := store.Issue(ctx, s.org, &g, audit.Event{
		Name: "grant.issued", Actor: evdomain.Actor{Type: "user", ID: owner.String()}, Outcome: audit.Success,
		Object: &audit.Object{Type: "grant", ID: g.ID.String()},
	}); err != nil {
		t.Fatal(err)
	}
	a.grant = g.ID

	// The issuer, the client binding, an allow-listed MCP client and the
	// org's MCP authorization, as approved changes would leave them.
	issuer := ids.NewV7()
	s.exec(t, `INSERT INTO pc.org_assertion_issuers (org_id, id, name, issuer, audience, algorithms, state, created_by, updated_by, activated_at)
		VALUES ($1, $2, 'okta', $3, $4, ARRAY['RS256'], 'ACTIVE', $5, $5, now())`, s.org, issuer, sim.Issuer(), iddomain.IssuerID(s.apiURL, s.org), owner)
	s.exec(t, `INSERT INTO pc.org_assertion_clients (org_id, id, issuer_id, client_id, agent_id, state, created_by, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, now())`, s.org, a.binding, issuer, idpClientID, a.agent, owner)
	mcpInstance := ids.NewV7()
	s.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'mcp_client')`, s.org, mcpInstance, a.agent, "unheld-"+mcpInstance.String())
	doc := ports.ClientMetadata{ClientID: idpMcpClient, Name: "Editor", RedirectURIs: []string{idpRedirect}}
	s.exec(t, `INSERT INTO pc.mcp_clients (org_id, id, client_url, agent_id, instance_id, state, created_by, activated_at, client_name,
		redirect_uris, document_digest) VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, now(), $7, $8, $9)`,
		s.org, a.client, idpMcpClient, a.agent, mcpInstance, owner, doc.Name, doc.RedirectURIs, idapp.DocumentDigest(doc))
	s.exec(t, `INSERT INTO pc.org_mcp_access (org_id, enabled, gateway_url, updated_by) VALUES ($1, true, $2, $3)`, s.org, s.gateway, owner)
	gw := s.gatewayID(t)
	s.exec(t, "UPDATE pc.gateways SET config_version = config_version + 1 WHERE id = $1", gw)
	s.waitConfig(t, s.configVersion(t, gw))

	// The token endpoint's use cases, with the server's mcp_tokens key.
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	reg := keys.NewRegistry()
	if err := keystore.LoadSigningKeys(ctx, s.pool, kp, reg); err != nil {
		t.Fatal(err)
	}
	minter := &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return reg.Signer(keys.PurposeMcpTokens) }), Issuer: s.apiURL}
	runs := runsapp.New(s.pool).WithGrants(&grantspg.Store{Pool: s.pool})
	a.ex = &idapp.Exchange{
		Pool: s.pool, PublicURL: s.apiURL, Clock: clock.System{}, Runs: runs, Tokens: minter,
		Verifier: &idjag.Verifier{Client: srv.Client(), CheckURL: func(string) error { return nil }},
	}
	a.flow = &idapp.CodeFlow{
		Pool: s.pool, PublicURL: s.apiURL, Clock: clock.System{}, Runs: runs, Tokens: minter,
		Documents: idpDocs{idpMcpClient: doc},
	}
	return a
}

// assert is an ID-JAG of the simulated IdP for sub at client, for the
// payments server unless resource says otherwise.
func (a *idpAccess) assert(t *testing.T, sub, client string, resource ...string) string {
	t.Helper()
	if len(resource) == 0 {
		resource = []string{a.resource}
	}
	j, err := a.sim.Assert(okta.Assertion{
		Subject: sub, ClientID: client, Audience: iddomain.IssuerID(a.s.apiURL, a.s.org), Resource: resource, Scope: "payments.refund.create",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return j
}

// clientAssertion is private_key_jwt for client, signed with key.
func (a *idpAccess) clientAssertion(t *testing.T, client string, key ed25519.PrivateKey, kid string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b, err := json.Marshal(map[string]any{
		"iss": client, "sub": client, "aud": a.s.apiURL + authnapp.TokenPath, "jti": ids.NewV7().String(),
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	obj, err := s.Sign(b)
	if err != nil {
		t.Fatal(err)
	}
	out, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// exchange is the jwt-bearer grant, authenticated with the seeded
// instance's key.
func (a *idpAccess) exchange(t *testing.T, assertion string) (authnapp.TokenResponse, error) {
	t.Helper()
	return a.exchangeAs(t, assertion, idpClientID, a.s.key, a.kid)
}

func (a *idpAccess) exchangeAs(t *testing.T, assertion, client string, key ed25519.PrivateKey, kid string) (authnapp.TokenResponse, error) {
	t.Helper()
	return a.ex.JWTBearer(context.Background(), url.Values{
		"grant_type": {idapp.GrantJWTBearer}, "assertion": {assertion},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {a.clientAssertion(t, client, key, kid)},
	})
}

// strangerKey is a key no instance holds, and its thumbprint.
func strangerKey(t *testing.T) (ed25519.PrivateKey, string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, thumbprint(t, pub)
}

// thumbprint is a key's RFC 7638 thumbprint, its instance's jkt.
func thumbprint(t *testing.T, pub ed25519.PublicKey) string {
	t.Helper()
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(tp)
}

// authorizeQuery is the allow-listed client's authorization request.
func (a *idpAccess) authorizeQuery() url.Values {
	h := sha256.Sum256([]byte(idpVerifier))
	return url.Values{
		"response_type": {"code"}, "client_id": {idpMcpClient}, "redirect_uri": {idpRedirect}, "state": {"e2e"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(h[:])}, "code_challenge_method": {"S256"}, "resource": {a.resource},
	}
}

// approve is the person's consent; it returns the code.
func (a *idpAccess) approve(t *testing.T) string {
	t.Helper()
	redirect, err := a.flow.Approve(context.Background(), a.s.org, a.person, a.authorizeQuery())
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("code")
}

func (a *idpAccess) redeem(code, verifier, redirect string) (authnapp.TokenResponse, error) {
	return a.flow.AuthorizationCode(context.Background(), url.Values{
		"grant_type": {idapp.GrantAuthorizationCode}, "code": {code}, "client_id": {idpMcpClient}, "redirect_uri": {redirect},
		"code_verifier": {verifier}, "resource": {a.resource},
	})
}

func (a *idpAccess) refresh(token string) (authnapp.TokenResponse, error) {
	return a.flow.Refresh(context.Background(), url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {idpMcpClient}})
}

// revoke has a security admin revoke the person's grant.
func (a *idpAccess) revoke(t *testing.T) {
	t.Helper()
	admin := a.s.person(t, "idp-grant-revoker", td.RoleSecurityAdmin)
	gs := &grantspg.Store{Pool: a.s.pool, Promotions: grantstest.OpenGate{}}
	svc := &grantsapp.Service{Repo: gs, Subjects: gs, Defs: &defspg.Store{Pool: a.s.pool}, Authz: grantsapp.SubjectAuthorizer{}, Clock: clock.System{}}
	if _, err := svc.Revoke(admin.ctx, a.grant, "e2e: stop the IdP person's agent"); err != nil {
		t.Fatal(err)
	}
}

// idpRefund is a 2026-07-28 tools/call of create_refund.
func idpRefund(amount string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_refund","arguments":` +
		`{"charge":"ch_1","amount":"` + amount + `","currency":"USD","reason":"duplicate"},` +
		`"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`
}

// call sends body to path on the gateway with headers, and returns the
// status, the WWW-Authenticate header and the body.
func (a *idpAccess) call(t *testing.T, path, body string, headers map[string]string) (int, string, string) {
	t.Helper()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, a.s.gateway+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "create_refund")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate"), string(b)
}

// bearer calls the payments server's OAuth route with an access token.
func (a *idpAccess) bearer(t *testing.T, token, amount string) (int, string) {
	t.Helper()
	status, _, body := a.call(t, iddomain.ResourcePath+idpConnection, idpRefund(amount), map[string]string{"Authorization": "Bearer " + token})
	return status, body
}

// papRoute calls the payments server's PAP/1 route with an access token
// as the workload token and no proof.
func (a *idpAccess) papRoute(t *testing.T, token, run, amount string) (int, string) {
	t.Helper()
	status, _, body := a.call(t, "/mcp/"+idpConnection, idpRefund(amount), map[string]string{
		"Authorization": "PAP " + token, gateway.HeaderRunID: run,
	})
	return status, body
}

// succeeded reports whether an MCP answer is a tool result that ran.
func succeeded(status int, body string) bool {
	return status == http.StatusOK && strings.Contains(body, `"isError":false`)
}

// oauthErr is an OAuth error's code and description.
func oauthErr(err error) (string, string) {
	var oe *authnapp.OAuthError
	if errors.As(err, &oe) {
		return oe.Code, oe.Description
	}
	if err == nil {
		return "", ""
	}
	return "error", err.Error()
}
