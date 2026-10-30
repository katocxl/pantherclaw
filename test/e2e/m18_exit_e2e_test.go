// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"github.com/go-jose/go-jose/v4"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/idps"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/keys/keystest"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/exceptions"
	"github.com/katocxl/pantherclaw/internal/protect"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M18_Exit is M18's exit journey (G0 M18 exit criteria, D178), one
// path per feature on one Enterprise stack. Fleet alerts, the Scope Admin
// and the CIDR key go through the running server; exception groups, the
// identity provider and the re-wrap run their services in the test against
// the stack's database, with an in-memory change ceremony. The re-wrap
// moves the org's keys off the server's KEK, so it runs last.
//
// Covers: PN-010.6, PN-012.7, PN-012.8, PN-012.10, F584, F602
func TestE2E_M18_Exit(t *testing.T) {
	s := start(t, options{budget: "1000.00", billing: true})
	if err := hostedPlans(t, s.pool).ApplyPlan(context.Background(), s.org, entitlements.Snapshot{
		PlanID: "enterprise", Edition: "enterprise", Status: entitlements.StatusActive, EventID: "evt_m18_exit", EventAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	t.Run("a silent gateway alerts once and recovers, a low version is flagged and served", s.m18Fleet)
	t.Run("a Scope Admin binds inside its scope and is refused above it", s.m18ScopeAdmin)
	t.Run("a CIDR key is refused from any other address", s.m18CIDRKey)
	t.Run("an exception group activates only against its approved cohort", s.m18ExceptionGroup)
	t.Run("an identity provider change is two-person, signs a person in and keeps the last sign-in", func(t *testing.T) { s.m18IdentityProvider(t, kp) })
	t.Run("a re-wrap moves keys to a new KEK", func(t *testing.T) { s.m18Rewrap(t, kp) })
}

// m18Account adds a service account and an API key of it, with scopes and,
// when any are given, the address ranges the key works from. An empty
// cidrs leaves the key unrestricted.
func (s *stack) m18Account(t *testing.T, name string, scopes, cidrs []string) (ids.UUID, string) {
	t.Helper()
	sa := ids.NewV7()
	s.exec(t, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, $3, 'e2e')", s.org, sa, name)
	tok, err := credential.New(credential.APIKey, credential.EnvTest, s.org)
	if err != nil {
		t.Fatal(err)
	}
	s.exec(t, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at, allowed_cidrs)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 'e2e', now() + interval '90 days', $8::text[]::cidr[])`,
		s.org, ids.NewV7(), sa, name, tok.Hash(), tok.Hint(), scopes, cidrs)
	return sa, tok.Reveal()
}

func (s *stack) m18BindOrg(t *testing.T, sa ids.UUID, role td.RoleName) {
	t.Helper()
	s.exec(t, "INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'e2e')",
		s.org, ids.NewV7(), string(role), sa)
}

// m18Transport sends key as the bearer and, when set, forwarded as
// X-Forwarded-For.
type m18Transport struct{ key, forwarded string }

func (m m18Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+m.key)
	if m.forwarded != "" {
		r.Header.Set("X-Forwarded-For", m.forwarded)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) m18Client(m m18Transport) *connect.Client {
	return connect.NewClient(connecthttp.NewTransport(&http.Client{Timeout: 10 * time.Second, Transport: m}, s.apiURL))
}

// m18Fleet: a gateway of the org reports a version below the minimum and is
// flagged and alerted once, while the running gateway, flagged too, keeps
// serving (HR-470). It then stops reporting, raises one silent alert however
// often the sweep runs, and one recovery alert when it reports again
// (HR-471). The sweeps are the server's own job.
func (s *stack) m18Fleet(t *testing.T) {
	ctx := context.Background()
	sa, key := s.m18Account(t, "m18-fleet", []string{string(td.PermGatewayManage), string(td.PermGatewayRead)}, nil)
	s.m18BindOrg(t, sa, td.RoleGatewayAdmin)
	admin := pantherclawv1connect.NewGatewayAdminServiceClient(s.m18Client(m18Transport{key: key}))

	gw := ids.NewV7()
	s.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge-m18', 'e2e')", s.org, gw)
	svc := gwapp.New(s.pool, nil, s.apiURL, clock.System{})
	report := func() {
		t.Helper()
		if err := svc.ReportStatus(ctx, gwapp.Identity{Org: s.org, Gateway: gw}, gwapp.ReplicaStatus{
			Replica: "r1", Version: "v1.2.3", Build: "e2e", ConfigVersion: 1,
		}); err != nil {
			t.Fatal(err)
		}
	}
	report()
	if _, err := admin.SetFleetPolicy(ctx, &pantherclawv1.SetFleetPolicyRequest{MinimumVersion: "v2.0.0", SilenceAfterSeconds: 120}); err != nil {
		t.Fatalf("SetFleetPolicy: %v", err)
	}

	jc, err := jobs.NewClient(s.pool, nil, jobs.Config{})
	if err != nil {
		t.Fatal(err)
	}
	sweep := func() error {
		return s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			return jobs.InsertTx(ctx, jc, tx, gwapp.FleetSweepOrgArgs{Org: s.org}, nil)
		})
	}
	alerts := func(kind string) string {
		return s.row(t, "SELECT count(*)::text FROM pc.notifications WHERE org_id = $1 AND type = $2 AND body LIKE '%' || $3::text || '%'", s.org, kind, gw.String())
	}
	alerted := func(kind string) {
		t.Helper()
		eventually(t, 45*time.Second, "one "+kind, func() (bool, error) {
			if err := sweep(); err != nil {
				return false, err
			}
			return alerts(kind) == "1", nil
		})
	}
	alerted("gateway.below_minimum")

	var edge *pantherclawv1.FleetGateway
	eventually(t, 45*time.Second, "both gateways flagged", func() (bool, error) {
		res, err := admin.ListFleet(ctx, &pantherclawv1.ListFleetRequest{})
		if err != nil {
			return false, err
		}
		flagged := 0
		for _, g := range res.GetGateways() {
			if g.GetBelowMinimum() {
				flagged++
			}
			if g.GetGatewayId() == gw.String() {
				edge = g
			}
		}
		return flagged >= 2 && edge != nil, nil
	})
	if r := edge.GetReplicas(); len(r) != 1 || r[0].GetCompliance() != pantherclawv1.VersionCompliance_VERSION_COMPLIANCE_BELOW_MINIMUM {
		t.Fatalf("the fleet view of the gateway: %+v", edge)
	}
	if code, r := s.refund(t, ids.NewV7(), "10.00"); code != http.StatusOK {
		t.Fatalf("a refund through a gateway below the minimum: %d %+v", code, r)
	}

	s.db.AdminExec(t, "UPDATE pc.gateway_alert_state SET last_report_at = now() - interval '10 minutes' WHERE org_id = $1 AND gateway_id = $2", s.org, gw)
	s.db.AdminExec(t, "UPDATE pc.gateway_replicas SET last_seen = now() - interval '10 minutes' WHERE org_id = $1 AND gateway_id = $2", s.org, gw)
	alerted("gateway.silent")
	again, err := gwapp.NewFleet(svc, enterprise{}, nil).Sweep(ctx, s.org)
	if err != nil {
		t.Fatal(err)
	}
	if again.Silent != 0 || again.Recovered != 0 {
		t.Fatalf("a second sweep of the silence: %+v", again)
	}
	report()
	alerted("gateway.recovered")
	if got := alerts("gateway.silent"); got != "1" {
		t.Fatalf("%s silent alerts, want 1", got)
	}
}

// m18ScopeAdmin: a Scope Admin at a team who is a Developer there binds
// Developer at the team. It is refused at the business unit, for a role it
// does not hold and at the organization (HR-472, HR-473).
func (s *stack) m18ScopeAdmin(t *testing.T) {
	bu, team, sibling, user := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	s.exec(t, "INSERT INTO pc.business_units (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", s.org, bu)
	s.exec(t, `INSERT INTO pc.teams (org_id, id, business_unit_id, slug, name) VALUES ($1, $2, $3, 'refunds', 'Refunds'), ($1, $4, $3, 'loans', 'Loans')`,
		s.org, team, bu, sibling)
	s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'm18-bound')", s.org, user)
	sa, key := s.m18Account(t, "m18-scope-admin", []string{string(td.PermRoleBind), string(td.PermRoleRead)}, nil)
	for _, role := range []td.RoleName{td.RoleScopeAdmin, td.RoleDeveloper} {
		s.exec(t, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, team_id, created_by)
			VALUES ($1, $2, $3, $4, 'TEAM', $5, 'e2e')`, s.org, ids.NewV7(), string(role), sa, team)
	}
	access := pantherclawv1connect.NewAccessServiceClient(s.m18Client(m18Transport{key: key}))
	bind := func(role td.RoleName, scope *pantherclawv1.Scope) error {
		_, err := access.CreateRoleBinding(context.Background(), &pantherclawv1.CreateRoleBindingRequest{
			Role: string(role), PrincipalType: pantherclawv1.PrincipalType_PRINCIPAL_TYPE_USER, PrincipalId: user.String(), Scope: scope,
		})
		return err
	}
	atTeam := &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_TEAM, Id: team.String()}
	if err := bind(td.RoleDeveloper, atTeam); err != nil {
		t.Fatalf("binding inside the team: %v", err)
	}
	for name, bad := range map[string]struct {
		role  td.RoleName
		scope *pantherclawv1.Scope
	}{
		"the business unit": {td.RoleDeveloper, &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_BUSINESS_UNIT, Id: bu.String()}},
		"a sibling team":    {td.RoleDeveloper, &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_TEAM, Id: sibling.String()}},
		"a role not held":   {td.RoleAgentOwner, atTeam},
		"the organization":  {td.RoleDeveloper, &pantherclawv1.Scope{Type: pantherclawv1.ScopeType_SCOPE_TYPE_ORG}},
	} {
		if err := bind(bad.role, bad.scope); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("%s: %v, want permission denied", name, err)
		}
	}
	if got := s.row(t, "SELECT count(*)::text FROM pc.role_bindings WHERE org_id = $1 AND user_id = $2", s.org, user); got != "1" {
		t.Fatalf("%s bindings, want the one inside the team", got)
	}
}

// m18CIDRKey: a key limited to the loopback ranges works from here; one
// limited to another range gets a bad key's error, and a forged
// X-Forwarded-For naming its range changes nothing (HR-475, HR-476).
func (s *stack) m18CIDRKey(t *testing.T) {
	scopes := []string{string(td.PermGatewayRead)}
	list := func(m m18Transport) error {
		_, err := pantherclawv1connect.NewGatewayAdminServiceClient(s.m18Client(m)).ListFleet(context.Background(), &pantherclawv1.ListFleetRequest{})
		return err
	}
	inside, here := s.m18Account(t, "m18-cidr-here", scopes, []string{"127.0.0.0/8", "::1/128"})
	s.m18BindOrg(t, inside, td.RoleGatewayAdmin)
	if err := list(m18Transport{key: here}); err != nil {
		t.Fatalf("a key from an allowed address: %v", err)
	}
	outside, there := s.m18Account(t, "m18-cidr-there", scopes, []string{"198.51.100.0/24"})
	s.m18BindOrg(t, outside, td.RoleGatewayAdmin)
	unknown, err := credential.New(credential.APIKey, credential.EnvTest, s.org)
	if err != nil {
		t.Fatal(err)
	}
	bad := list(m18Transport{key: unknown.Reveal()})
	if connect.CodeOf(bad) != connect.CodeUnauthenticated {
		t.Fatalf("an unknown key: %v", bad)
	}
	for name, m := range map[string]m18Transport{
		"from another address": {key: there},
		"with a forged header": {key: there, forwarded: "198.51.100.7"},
	} {
		if err := list(m); connect.CodeOf(err) != connect.CodeUnauthenticated || err.Error() != bad.Error() {
			t.Errorf("%s: %v, want a bad key's %v", name, err, bad)
		}
	}
}

// m18Changes stands in for the EXCEPTION change request; the test applies
// what it files, as the confirming transaction does.
type m18Changes struct{}

func (m18Changes) Request(_ context.Context, kind papp.ChangeKind, subject, _ ids.UUID, _ [32]byte, _ any) (papp.ChangeRequest, error) {
	return papp.ChangeRequest{ID: ids.NewV7(), Kind: kind, Subject: subject}, nil
}

// m18ExceptionGroup: a request binds the digest of the cohort's definition.
// Approving it after the cohort changed is void and waives nothing; a new
// request approved against the unchanged cohort covers the members at
// approval and not an agent that joins afterwards (HR-477).
func (s *stack) m18ExceptionGroup(t *testing.T) {
	const operation = "payments.refund.create"
	s.publishPolicy(t, `{"id": "no-refunds", "rules": [{"id": "no-refunds", "kind": "FORBID", "summary": "no refunds", `+
		`"operations": ["payments.refund.create"], "when": "true", "reason": "NO_REFUNDS", "exceptable": true}]}`)
	svc := &exceptions.Service{Pool: s.pool, Changes: m18Changes{}, Editions: enterprise{}}
	author, publisher := s.person(t, "m18-author", td.RolePolicyAuthor), s.person(t, "m18-publisher", td.RolePolicyPublisher)
	caller, err := tapp.CallerFrom(author.ctx)
	if err != nil {
		t.Fatal(err)
	}
	agent := mustUUID(t, s.row(t, "SELECT agent_id::text FROM pc.runs WHERE id = $1", s.run))
	cohort := ids.NewV7()
	s.exec(t, "INSERT INTO pc.fleet_cohorts (org_id, id, name, owner_user_id, created_by) VALUES ($1, $2, 'refunders', $3, 'e2e')", s.org, cohort, caller.Principal.ID)
	join := func(a ids.UUID) {
		t.Helper()
		s.exec(t, "INSERT INTO pc.fleet_cohort_members (org_id, cohort_id, agent_id, added_by) VALUES ($1, $2, $3, 'e2e')", s.org, cohort, a)
	}
	newAgent := func(name string) ids.UUID {
		t.Helper()
		a := ids.NewV7()
		s.exec(t, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, $3, 'DISCOVERED', 'e2e')", s.org, a, name)
		return a
	}
	join(agent)
	request := func() ids.UUID {
		t.Helper()
		g, _, err := svc.RequestGroup(author.ctx, exceptions.GroupRequest{
			Rule: "no-refunds", Cohort: cohort, Operations: []string{operation}, Reason: "Quarter-end backlog of reviewed refunds.", ExpiresIn: 7 * 24 * time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return g.ID
	}
	approve := func(group ids.UUID) error {
		return s.pool.InTenantTx(publisher.ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
			return svc.Apply(ctx, tx, papp.ChangeRequest{ID: ids.NewV7(), Kind: papp.ChangeException, Subject: group})
		})
	}
	active := func(a ids.UUID) []pdomain.Exception {
		t.Helper()
		var out []pdomain.Exception
		if err := s.pool.InTenantTx(context.Background(), s.org, func(ctx context.Context, tx db.TenantTx) error {
			var err error
			out, err = exceptions.ActiveFor(ctx, tx, s.org, a)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}

	widened := request()
	join(newAgent("m18-widened"))
	var void *papp.VoidError
	if err := approve(widened); !errors.As(err, &void) || void.Reason != papp.VoidBaseChanged {
		t.Fatalf("approving after the cohort changed: %v", err)
	}
	if x := active(agent); len(x) != 0 {
		t.Fatalf("a void request waived the rule: %v", x)
	}
	group := request()
	if err := approve(group); err != nil {
		t.Fatalf("approving against the unchanged cohort: %v", err)
	}
	if x := active(agent); len(x) != 1 || x[0].Rule != "no-refunds" {
		t.Fatalf("a member at approval: %v", x)
	}
	late := newAgent("m18-late")
	join(late)
	if x := active(late); len(x) != 0 {
		t.Fatalf("an agent that joined after approval is covered: %v", x)
	}
}

// m18Requests is an in-memory change ceremony; the protected-change records
// and the Gate are the real ones.
type m18Requests map[ids.UUID]bool

func (r m18Requests) Open(context.Context, db.TenantTx, protect.Request) (ids.UUID, error) {
	id := ids.NewV7()
	r[id] = true
	return id, nil
}

func (r m18Requests) Void(_ context.Context, _ db.TenantTx, id ids.UUID, _ string) error {
	delete(r, id)
	return nil
}

func (r m18Requests) Pending(_ context.Context, _ db.TenantTx, id ids.UUID) (bool, error) {
	return r[id], nil
}

// m18Issuer is a TLS OpenID provider standing in for an organization's own
// at issuer. A running server cannot reach a local one, by HR-483: the
// Resolver's client (tests only) dials this server whatever the host.
type m18Issuer struct {
	client *http.Client
	nonce  atomic.Pointer[string]
}

func newM18Issuer(t *testing.T, issuer, clientID, subject string) *m18Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	m := &m18Issuer{}
	write := func(w http.ResponseWriter, v any) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		write(w, map[string]any{
			"issuer": issuer, "authorization_endpoint": issuer + "/auth", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/jwks",
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		write(w, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now()
		claims, err := json.Marshal(map[string]any{
			"iss": issuer, "sub": subject, "aud": []string{clientID}, "nonce": *m.nonce.Load(), "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
			"email": "alice@example.test", "email_verified": true, "name": "Alice",
		})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		signed, err := signer.Sign(claims)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		token, err := signed.CompactSerialize()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		write(w, map[string]any{"access_token": "m18-access", "token_type": "Bearer", "expires_in": 300, "id_token": token})
	})
	srv := httptest.NewTLSServer(mux)
	t.Cleanup(srv.Close)
	m.client = srv.Client()
	tr := m.client.Transport.(*http.Transport).Clone()
	addr := srv.Listener.Addr().String()
	tr.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}
	tr.TLSClientConfig.InsecureSkipVerify = true //nolint:gosec // G402: the test server stands in for the issuer's host
	m.client.Transport = tr
	m.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return m
}

// m18IdentityProvider: an organization identity provider waits for a second
// person and signs nobody in before that. Once confirmed, a person signs in
// through it to a session of that org, and another org's provider is refused
// here at both ends of the sign-in. Then, as the org's only sign-in path, it
// cannot be disabled (PN-012.7, HR-481, HR-484). The sign-in runs the real
// Browser and Resolver in the test: HR-483 keeps a running server from any
// local provider, and no test seam goes around it (D179).
func (s *stack) m18IdentityProvider(t *testing.T, kp keys.KeyProvider) {
	ctx := context.Background()
	const issuer, rivalIssuer, clientID = "https://idp.example.com", "https://rival.example.com", "pc-client"
	alice, bob := ids.NewV7(), ids.NewV7()
	for u, from := range map[ids.UUID]string{alice: issuer, bob: "https://corp.example.com"} {
		s.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", s.org, u, from, u.String())
		s.exec(t, "INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'e2e')",
			s.org, ids.NewV7(), string(td.RoleOrgAdmin), u)
	}
	rival, carol, dan := ids.New[ids.Org](), ids.NewV7(), ids.NewV7()
	s.db.AdminExec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'rival')", rival)
	for _, u := range []ids.UUID{carol, dan} {
		s.db.AdminExec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, $3, $4)", rival, u, rivalIssuer, u.String())
		s.db.AdminExec(t, "INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by) VALUES ($1, $2, $3, $4, 'ORG', 'e2e')",
			rival, ids.NewV7(), string(td.RoleOrgAdmin), u)
	}
	as := func(org ids.OrgID, u ids.UUID) context.Context {
		return tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: u},
			Bindings: []td.Binding{{Role: td.RoleOrgAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		}, Credential: tapp.CredBrowserSession})
	}
	fake := newM18Issuer(t, issuer, clientID, alice.String())
	store := &idps.Store{Envelope: pccrypto.NewEnvelope(keystore.NewDEKStore(s.pool, kp))}
	gate := &protect.Gate{Requests: m18Requests{}}
	svc := &idps.Service{Pool: s.pool, Store: store, Gate: gate, Editions: enterprise{}}
	svc.Register(gate)
	resolver := &idps.Resolver{Pool: s.pool, Store: store, HTTPClient: fake.client}
	resolved := func() []string {
		t.Helper()
		own, _, err := resolver.OrgProviders(ctx, s.org)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, p := range own {
			names = append(names, p.Name())
		}
		return names
	}
	confirm := func(org ids.OrgID, f idps.Filed, u ids.UUID) error {
		return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			return gate.Apply(ctx, tx, f.Request, []ids.UUID{u})
		})
	}
	input := func(name, from string) idps.Input {
		return idps.Input{Name: name, Issuer: from, ClientID: clientID, ClientSecret: pclog.NewSecret([]byte("s3cr3t-value-for-test"))}
	}

	p, f, err := svc.Create(as(s.org, alice), input("acme", issuer))
	if err != nil {
		t.Fatal(err)
	}
	if p.State != idps.StatePending || len(resolved()) != 0 {
		t.Fatalf("a provider signs in before its confirmation: %+v", p)
	}
	if err := confirm(s.org, f, alice); err == nil {
		t.Fatal("the author confirmed their own change")
	}
	if err := confirm(s.org, f, bob); err != nil {
		t.Fatal(err)
	}
	if got := resolved(); !slices.Equal(got, []string{"acme"}) {
		t.Fatalf("confirmed provider not resolved: %v", got)
	}
	_, f2, err := svc.Create(as(rival, carol), input("rival", rivalIssuer))
	if err != nil {
		t.Fatal(err)
	}
	if err := confirm(rival, f2, dan); err != nil {
		t.Fatal(err)
	}

	browser := authnapp.NewBrowser(s.pool, s.apiURL, nil, clock.System{}, nil).WithOrgProviders(resolver)
	begin := func() (authnapp.Redirect, url.Values) {
		t.Helper()
		red, err := browser.Start(ctx, authnapp.BrowserStart{Org: s.org.String(), Provider: "acme", ClientIP: "127.0.0.1"})
		if err != nil {
			t.Fatalf("starting a sign-in: %v", err)
		}
		u, err := url.Parse(red.URL)
		if err != nil || u.Scheme+"://"+u.Host != issuer {
			t.Fatalf("the sign-in went to %q (%v)", red.URL, err)
		}
		nonce := u.Query().Get("nonce")
		fake.nonce.Store(&nonce)
		return red, url.Values{"state": {u.Query().Get("state")}, "code": {"m18-code"}, "iss": {issuer}}
	}
	meta := authnapp.ClientMeta{IP: "127.0.0.1"}
	red, params := begin()
	in, err := browser.Callback(ctx, "acme", params, red.Binding, meta)
	if err != nil || in.Reason != "" || in.Secret == "" || in.Org != s.org {
		t.Fatalf("signing in through the org's provider: %+v %v", in, err)
	}
	if got := s.row(t, "SELECT user_id::text || ' ' || provider FROM pc.browser_sessions WHERE org_id = $1 AND id = $2", s.org, in.Session); got != alice.String()+" acme" {
		t.Fatalf("the session: %q", got)
	}

	if _, err := browser.Start(ctx, authnapp.BrowserStart{Org: s.org.String(), Provider: "rival", ClientIP: "127.0.0.1"}); !errors.Is(err, authnapp.ErrSignInUnavailable) {
		t.Fatalf("starting a sign-in through another org's provider: %v", err)
	}
	red, params = begin()
	if got, err := browser.Callback(ctx, "rival", params, red.Binding, meta); !errors.Is(err, authnapp.ErrBadCallback) {
		t.Fatalf("a callback naming another org's provider: %+v %v", got, err)
	}

	if _, err := svc.Disable(as(s.org, alice), p.ID); !errors.Is(err, idps.ErrLockOut) {
		t.Fatalf("the last sign-in path was filed for disabling: %v", err)
	}
	if got := resolved(); !slices.Equal(got, []string{"acme"}) {
		t.Fatalf("the provider after the refused disable: %v", got)
	}
}

// m18Rewrap: the org's file-wrapped data keys move to an OpenBao-style
// Transit KEK and still unwrap through it alone. With the key service down,
// a new key fails closed (HR-486, HR-487).
func (s *stack) m18Rewrap(t *testing.T, kp *keys.FileProvider) {
	ctx := context.Background()
	const purpose = "m18_exit"
	file, err := keys.NewRouter(keys.PrefixFile, kp, nil)
	if err != nil {
		t.Fatal(err)
	}
	version, dek, err := keystore.NewDEKStore(s.pool, file).CurrentDEK(ctx, s.org, purpose)
	if err != nil {
		t.Fatal(err)
	}

	f := keystest.NewTransit(t)
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte(f.Token), 0o600); err != nil {
		t.Fatal(err)
	}
	transit, err := keys.NewTransitClient(keys.OpenBaoConfig{
		Address: f.Srv.URL, KeyName: keystest.KeyName, Auth: keys.OpenBaoAuth{Kind: keys.AuthToken, TokenFile: token},
	})
	if err != nil {
		t.Fatal(err)
	}
	bao := keys.NewOpenBaoProvider(transit)
	both, err := keys.NewRouter(keys.PrefixOpenBao, kp, bao)
	if err != nil {
		t.Fatal(err)
	}
	res, err := keystore.RewrapOrg(ctx, s.pool, s.db.Pool(t, s.db.Keystore), both, s.org)
	if err != nil {
		t.Fatal(err)
	}
	if res.DEKs == 0 {
		t.Fatalf("re-wrapped %+v", res)
	}
	if got := s.row(t, "SELECT string_agg(DISTINCT kek_id, ' ') FROM pc.deks WHERE org_id = $1", s.org); got != "bao:"+keystest.KeyName {
		t.Fatalf("data keys under %q", got)
	}
	baoOnly, err := keys.NewRouter(keys.PrefixOpenBao, nil, bao)
	if err != nil {
		t.Fatal(err)
	}
	got, err := keystore.NewDEKStore(s.pool, baoOnly).DEK(ctx, s.org, purpose, version)
	if err != nil || string(got.Reveal()) != string(dek.Reveal()) {
		t.Fatalf("the data key after the re-wrap: %v", err)
	}
	f.Down.Store(true)
	if _, _, err := keystore.NewDEKStore(s.pool, baoOnly).CurrentDEK(ctx, s.org, purpose+"_new"); err == nil {
		t.Fatal("a new key was made with the key service down")
	}
}
