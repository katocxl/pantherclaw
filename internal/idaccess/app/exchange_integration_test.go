// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idjag"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	"github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	"github.com/katocxl/pantherclaw/internal/sim/okta"
)

const (
	publicURL = "https://pc.example.com"
	gateway   = "https://gw.example.com"
	clientID  = "0oa-agent-client"
)

var resource = domain.ResourceURL(gateway, "github")

type env struct {
	pool     *db.Pool
	org      ids.OrgID
	user     ids.UUID
	other    ids.UUID
	agent    ids.UUID
	envID    ids.UUID
	instance ids.UUID
	key      ed25519.PrivateKey
	kid      string
	issuer   ids.UUID
	binding  ids.UUID
	sim      *okta.Sim
	ex       *app.Exchange
}

func (e *env) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.InTenantTx(context.Background(), e.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func newEnv(t *testing.T) *env {
	t.Helper()
	var h http.Handler
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { h.ServeHTTP(w, r) }))
	t.Cleanup(srv.Close)
	sim, err := okta.New(srv.URL, okta.Faults{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	h = sim.Handler()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tp, err := (&jose.JSONWebKey{Key: pub}).Thumbprint(crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := json.Marshal(map[string]string{"kty": "OKP", "crv": "Ed25519", "x": base64.RawURLEncoding.EncodeToString(pub)})
	if err != nil {
		t.Fatal(err)
	}
	e := &env{
		pool: dbtest.New(t).AppPool(t), org: ids.New[ids.Org](), user: ids.NewV7(), other: ids.NewV7(), agent: ids.NewV7(),
		envID: ids.NewV7(), instance: ids.NewV7(), key: priv, kid: base64.RawURLEncoding.EncodeToString(tp),
		issuer: ids.NewV7(), binding: ids.NewV7(), sim: sim,
	}
	team := ids.NewV7()
	e.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'm26')", e.org)
	e.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", e.org, team)
	e.exec(t, `INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')`,
		e.org, e.envID, team)
	for i, u := range []ids.UUID{e.user, e.other} {
		e.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", e.org, u, sim.Issuer(),
			[]string{"00u-alice", "00u-bob"}[i])
	}
	e.exec(t, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by,
		claimed_at) VALUES ($1, $2, 'coder', $3, $4, $5, 'ci', 'CLAIMED', 'test', now())`, e.org, e.agent, team, e.envID, e.user)
	e.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, $5, 'ADMITTED', 'discovery')`, e.org, e.instance, e.agent, e.kid, jwk)
	e.grant(t, `{"operations":["tickets.read","tickets.write"]}`)
	e.exec(t, `INSERT INTO pc.org_assertion_issuers (org_id, id, name, issuer, audience, algorithms, state, created_by, updated_by, activated_at)
		VALUES ($1, $2, 'okta', $3, $4, ARRAY['RS256'], 'ACTIVE', $5, $5, now())`,
		e.org, e.issuer, sim.Issuer(), domain.IssuerID(publicURL, e.org), e.user)
	e.exec(t, `INSERT INTO pc.org_assertion_clients (org_id, id, issuer_id, client_id, agent_id, state, created_by, activated_at)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6, now())`, e.org, e.binding, e.issuer, clientID, e.agent, e.user)
	e.exec(t, `INSERT INTO pc.org_mcp_access (org_id, enabled, gateway_url, updated_by) VALUES ($1, true, $2, $3)`, e.org, gateway, e.user)
	_, signKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jws.NewSigner("mcp-1", signKey)
	if err != nil {
		t.Fatal(err)
	}
	e.ex = &app.Exchange{
		Pool: e.pool, PublicURL: publicURL, Clock: clock.System{},
		Verifier: &idjag.Verifier{Client: srv.Client(), CheckURL: func(string) error { return nil }},
		Runs:     runsapp.New(e.pool).WithGrants(&grantspg.Store{Pool: e.pool}),
		Tokens:   &mcptoken.Minter{Keys: mcptoken.SignerFunc(func() (*jws.Signer, error) { return signer, nil }), Issuer: publicURL},
	}
	return e
}

// grant gives the user a root grant of the agent with bounds.
func (e *env) grant(t *testing.T, bounds string) ids.UUID {
	t.Helper()
	g := ids.NewV7()
	e.exec(t, `INSERT INTO pc.grants (org_id, id, agent_id, principal_user_id, environment_id, depth, current_revision, grantor_kind,
		grantor_id, basis) VALUES ($1, $2, $3, $4, $5, 0, 1, 'user', $4, 'test')`, e.org, g, e.agent, e.user, e.envID)
	e.exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by)
		VALUES ($1, $2, $3, 1, now() - interval '1 minute', now() + interval '1 day', $4, '[]', '{}', 0, 0, 0, false, 'test')`,
		e.org, ids.NewV7(), g, []byte(bounds))
	return g
}

func (e *env) assert(t *testing.T, sub, client, scope string, resources ...string) string {
	t.Helper()
	if len(resources) == 0 {
		resources = []string{resource}
	}
	a, err := e.sim.Assert(okta.Assertion{
		Subject: sub, ClientID: client, Audience: domain.IssuerID(publicURL, e.org), Resource: resources, Scope: scope,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// clientAssertion is private_key_jwt signed with key.
func (e *env) clientAssertion(t *testing.T, key ed25519.PrivateKey, kid string) string {
	t.Helper()
	s, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: key, KeyID: kid}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	b, err := json.Marshal(map[string]any{
		"iss": clientID, "sub": clientID, "aud": publicURL + authnapp.TokenPath, "jti": ids.NewV7().String(),
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

func (e *env) exchange(t *testing.T, assertion string, extra url.Values) (authnapp.TokenResponse, error) {
	t.Helper()
	form := url.Values{
		"grant_type": {app.GrantJWTBearer}, "assertion": {assertion},
		"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {e.clientAssertion(t, e.key, e.kid)},
	}
	for k, v := range extra {
		form[k] = v
	}
	return e.ex.JWTBearer(context.Background(), form)
}

func oauthCode(err error) string {
	var oe *authnapp.OAuthError
	if errors.As(err, &oe) {
		return oe.Code + " " + oe.Description
	}
	if err == nil {
		return "ok"
	}
	return "error " + err.Error()
}

// TestHR620_AnAssertionUsesOrNarrowsAnExistingGrantAndWritesNone: a valid
// assertion starts an id_jag run bound to the person's existing grant,
// narrowed by the scope, with the client's instance as launcher; no grant
// row is written, and the token is a pap-mcp+jwt for one server.
//
// Covers: F910
func TestHR620_AnAssertionUsesOrNarrowsAnExistingGrantAndWritesNone(t *testing.T) {
	e := newEnv(t)
	before := e.count(t, "SELECT count(*) FROM pc.grants")
	res, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read openid"), nil)
	if err != nil {
		t.Fatalf("exchange: %v", oauthCode(err))
	}
	if res.TokenType != "Bearer" || res.Scope != "tickets.read" || res.RunID == "" || res.RefreshToken != "" || res.ExpiresIn > 300 {
		t.Fatalf("response: %+v", res)
	}
	if _, typ, err := jws.Unverified(res.AccessToken); err != nil || typ != mcptoken.TokenType {
		t.Fatalf("token typ %q %v", typ, err)
	}
	if n := e.count(t, "SELECT count(*) FROM pc.grants"); n != before {
		t.Fatalf("grants %d -> %d", before, n)
	}
	if n := e.count(t, `SELECT count(*) FROM pc.runs WHERE id = $1 AND principal_source = 'id_jag' AND launcher_instance_id = $2
		AND instance_id = $2 AND principal_user_id = $3 AND subject_subject = '00u-alice' AND scope_operations = ARRAY['tickets.read']
		AND grant_id IS NOT NULL AND parent_run_id IS NULL`, res.RunID, e.instance, e.user); n != 1 {
		t.Fatal("the run is not the id_jag run bound to the grant")
	}
}

// TestHR621_SeveralGrantsFailClosedUntilTheScopeNamesOne: a second matching
// grant refuses an assertion that names none; naming one works.
//
// Covers: F910
func TestHR621_SeveralGrantsFailClosedUntilTheScopeNamesOne(t *testing.T) {
	e := newEnv(t)
	second := e.grant(t, `{"operations":["tickets.read"]}`)
	if _, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil); !strings.HasPrefix(oauthCode(err),
		"access_denied "+app.ReasonAmbiguousGrant) {
		t.Fatalf("two grants: %v", oauthCode(err))
	}
	res, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "pc.grant:"+second.String()), nil)
	if err != nil || res.RunID == "" {
		t.Fatalf("named grant: %v", oauthCode(err))
	}
	if n := e.count(t, "SELECT count(*) FROM pc.runs WHERE id = $1 AND grant_id = $2", res.RunID, second); n != 1 {
		t.Fatal("the run does not use the named grant")
	}
}

// TestHR622_TokenEndpointRefusals: the refusals the token endpoint owns,
// each with the draft -06 §4.4.3 code.
//
// Covers: F910, F911
func TestHR622_TokenEndpointRefusals(t *testing.T) {
	e := newEnv(t)
	other := domain.ResourceURL("https://gw.other.example.com", "github")
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
	replayed := e.assert(t, "00u-alice", clientID, "tickets.read")
	if _, err := e.exchange(t, replayed, nil); err != nil {
		t.Fatalf("first use: %v", oauthCode(err))
	}
	cases := []struct {
		name, want string
		run        func() error
	}{
		{"no grant", "access_denied " + app.ReasonNoGrant, func() error {
			_, err := e.exchange(t, e.assert(t, "00u-bob", clientID, "tickets.read"), nil)
			return err
		}},
		{"scope outside the grant", "access_denied " + app.ReasonNoGrant, func() error {
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "payments.refund"), nil)
			return err
		}},
		{"replayed assertion", "invalid_grant", func() error { _, err := e.exchange(t, replayed, nil); return err }},
		{"a person not linked", "invalid_grant", func() error {
			_, err := e.exchange(t, e.assert(t, "00u-nobody", clientID, "tickets.read"), nil)
			return err
		}},
		{"an unlisted client", "invalid_client", func() error {
			_, err := e.exchange(t, e.assert(t, "00u-alice", "0oa-unlisted", "tickets.read"), nil)
			return err
		}},
		{"a client key not admitted", "invalid_client", func() error {
			form := url.Values{
				"grant_type": {app.GrantJWTBearer}, "assertion": {e.assert(t, "00u-alice", clientID, "tickets.read")},
				"client_assertion_type": {authnapp.AssertionType}, "client_assertion": {e.clientAssertion(t, otherKey, "not-admitted")},
			}
			_, err := e.ex.JWTBearer(context.Background(), form)
			return err
		}},
		{"no client authentication", "invalid_client", func() error {
			_, err := e.ex.JWTBearer(context.Background(), url.Values{
				"grant_type": {app.GrantJWTBearer},
				"assertion":  {e.assert(t, "00u-alice", clientID, "tickets.read")},
			})
			return err
		}},
		{"a token for another server", "invalid_grant", func() error {
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read", other), nil)
			return err
		}},
		{"a resource the assertion does not name", "invalid_grant", func() error {
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), url.Values{"resource": {other}})
			return err
		}},
		{"a wider request scope", "invalid_grant", func() error {
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), url.Values{"scope": {"tickets.write"}})
			return err
		}},
		{"wrong audience", "invalid_grant", func() error {
			e.sim.SetFaults(okta.Faults{WrongAudience: true})
			defer e.sim.SetFaults(okta.Faults{})
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil)
			return err
		}},
		{"expired", "invalid_grant", func() error {
			e.sim.SetFaults(okta.Faults{Expired: true})
			defer e.sim.SetFaults(okta.Faults{})
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil)
			return err
		}},
		{"cnf", "invalid_grant", func() error {
			e.sim.SetFaults(okta.Faults{Cnf: true})
			defer e.sim.SetFaults(okta.Faults{})
			_, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil)
			return err
		}},
	}
	for _, c := range cases {
		if got := oauthCode(c.run()); !strings.HasPrefix(got, c.want) {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// Turning things off applies at once (HR-141).
	e.exec(t, "UPDATE pc.org_mcp_access SET enabled = false WHERE org_id = $1", e.org)
	if _, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil); !strings.HasPrefix(oauthCode(err),
		"access_denied "+app.ReasonMcpAccessOff) {
		t.Errorf("MCP authorization off: %v", oauthCode(err))
	}
	e.exec(t, "UPDATE pc.org_mcp_access SET enabled = true WHERE org_id = $1", e.org)
	e.exec(t, "UPDATE pc.org_assertion_clients SET state = 'REMOVED', removed_by = $2, removed_at = now() WHERE id = $1", e.binding, e.user)
	if _, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil); !strings.HasPrefix(oauthCode(err), "invalid_client") {
		t.Errorf("a removed binding: %v", oauthCode(err))
	}
	e.exec(t, "UPDATE pc.org_assertion_issuers SET state = 'DISABLED', disabled_by = $2, disabled_at = now() WHERE id = $1", e.issuer, e.user)
	if _, err := e.exchange(t, e.assert(t, "00u-alice", clientID, "tickets.read"), nil); !strings.HasPrefix(oauthCode(err), "invalid_grant") {
		t.Errorf("a disabled issuer: %v", oauthCode(err))
	}
}
