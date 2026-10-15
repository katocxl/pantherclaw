// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package grantsrpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/grantsrpc"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type stack struct {
	pool   *db.Pool
	tokens *token.Service
	url    string
}

func newStack(t *testing.T) *stack {
	t.Helper()
	pool := dbtest.New(t).AppPool(t)
	reg := keys.NewRegistry()
	for _, p := range keys.Purposes() {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			t.Fatal(err)
		}
		if err := reg.Put(k); err != nil {
			t.Fatal(err)
		}
	}
	tokens, err := token.New(reg, "https://pc.example.test", token.Audience)
	if err != nil {
		t.Fatal(err)
	}
	authn, err := authnapp.NewAuthenticator(pool, tokens, credential.EnvTest, clock.System{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	declared, err := protoperms.Declared(filepath.Join("..", "..", "..", "..", "proto"))
	if err != nil {
		t.Fatal(err)
	}
	perms := map[string]td.Permission{}
	for proc, p := range declared {
		perms[proc] = td.Permission(p)
	}
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(authn, perms, nil, rpcauth.WithRefusals(&rpcauth.AuditRefusals{Pool: pool}))})
	if err != nil {
		t.Fatal(err)
	}
	store := &pgstore.Store{Pool: pool}
	svc := &app.Service{
		Repo: store, Subjects: store, Defs: &defspg.Store{Pool: pool}, Authz: app.SubjectAuthorizer{},
		Clock: clock.System{}, Listing: store,
	}
	pantherclawv1connect.RegisterGrantServiceHandler(s, grantsrpc.NewGrants(svc))
	pantherclawv1connect.RegisterGuardrailServiceHandler(s, grantsrpc.NewGuardrails(svc))
	mux := http.NewServeMux()
	rpc.Mount(mux, s)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &stack{pool: pool, tokens: tokens, url: ts.URL}
}

func (s *stack) exec(t *testing.T, org ids.OrgID, sql string, args ...any) {
	t.Helper()
	if err := s.pool.InTenantTx(context.Background(), org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// login creates a user with roles at org scope and returns its id and a
// bearer token.
func (s *stack) login(t *testing.T, org ids.OrgID, subject string, roles ...td.RoleName) (ids.UUID, string) {
	t.Helper()
	user, session := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", org, user, subject)
	for _, role := range roles {
		s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), user)
	}
	s.exec(t, org, `INSERT INTO pc.cli_sessions (org_id, id, user_id, device_jkt, device_jwk, refresh_hash, expires_at)
		VALUES ($1, $2, $3, repeat('d', 43), '{}', $4, now() + interval '8 hours')`, org, session, user, user.String()[:32])
	tok, _, err := s.tokens.Issue(token.Grant{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: user}, Session: session, ClientID: "pclaw",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return user, tok
}

// apiKey creates a service account with roles at org scope and returns an
// API key for it.
func (s *stack) apiKey(t *testing.T, org ids.OrgID, scopes []string, roles ...td.RoleName) string {
	t.Helper()
	sa := ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.service_accounts (org_id, id, name, created_by) VALUES ($1, $2, 'ci', 'test')", org, sa)
	for _, role := range roles {
		s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, service_account_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), sa)
	}
	key, err := credential.New(credential.APIKey, credential.EnvTest, org)
	if err != nil {
		t.Fatal(err)
	}
	s.exec(t, org, `INSERT INTO pc.api_keys (org_id, id, service_account_id, name, secret_hash, hint, scopes, created_by, expires_at)
		VALUES ($1, $2, $3, 'deploy', $4, $5, $6, 'test', now() + interval '90 days')`,
		org, ids.NewV7(), sa, key.Hash(), key.Hint(), scopes)
	return key.Reveal()
}

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) clients(tok string) (pantherclawv1connect.GrantServiceClient, pantherclawv1connect.GuardrailServiceClient) {
	tr := connecthttp.NewTransport(&http.Client{Transport: bearer{tok}}, s.url)
	return pantherclawv1connect.NewGrantServiceClient(connect.NewClient(tr)), pantherclawv1connect.NewGuardrailServiceClient(connect.NewClient(tr))
}

func wantCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Errorf("%s: %v, want %s", what, err, want)
	}
}

type org struct {
	team, env, agent, owner ids.UUID
	org                     ids.OrgID
}

func seed(t *testing.T, s *stack) org {
	t.Helper()
	o := org{org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), agent: ids.NewV7(), owner: ids.NewV7()}
	s.exec(t, o.org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", o.org)
	if err := s.pool.InTenantTx(context.Background(), o.org, func(ctx context.Context, tx db.TenantTx) error {
		return dbq.New(tx).InsertContainment(ctx, o.org)
	}); err != nil {
		t.Fatal(err)
	}
	s.exec(t, o.org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'payments', 'Payments')", o.org, o.team)
	s.exec(t, o.org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'prod', 'Prod', 'PRODUCTION')", o.org, o.env, o.team)
	s.exec(t, o.org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'owner')", o.org, o.owner)
	s.exec(t, o.org, `INSERT INTO pc.agents (org_id, id, name, team_id, environment_id, owner_user_id, execution_context, state, created_by, claimed_at)
		VALUES ($1, $2, 'refund-bot', $3, $4, $5, 'service', 'VERIFIED', 'test', now())`, o.org, o.agent, o.team, o.env, o.owner)
	return o
}

const bounds = `{"operations": ["payments.refund.create"], "targets": {"payments.charge": {"prefixes": ["ch_"]}}}`

// TestIntRPCGrantsAndGuardrails drives GrantService and GuardrailService
// end to end: guardrails, issuance inside them, revision, lineage, the
// effective bounds, budget state, listing, revocation, and the refusals of
// HR-161 (only people issue grants or change guardrails) and of other orgs.
func TestIntRPCGrantsAndGuardrails(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	o := seed(t, s)
	admin, adminTok := s.login(t, o.org, "admin", td.RoleGrantIssuer, td.RolePolicyPublisher)
	grants, guardrails := s.clients(adminTok)
	principal := &pantherclawv1.Actor{Kind: "user", Id: admin.String()}

	// An org guardrail allows refunds on charges only, for at most 3 days.
	env, err := guardrails.CreateEnvelope(ctx, &pantherclawv1.CreateEnvelopeRequest{
		Scope: &pantherclawv1.GuardrailScope{Kind: pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG},
		Name:  "org", Bounds: []byte(`{"operations": ["payments.*"]}`),
		Settings: &pantherclawv1.GuardrailSettings{MaxRootLifetime: durationpb.New(72 * time.Hour)},
	})
	if err != nil || env.GetEnvelope().GetRevision() != 1 || env.GetEnvelope().GetChangedBy().GetId() != admin.String() {
		t.Fatalf("CreateEnvelope = %v, %v", env, err)
	}
	_, err = guardrails.CreateEnvelope(ctx, &pantherclawv1.CreateEnvelopeRequest{
		Scope: &pantherclawv1.GuardrailScope{Kind: pantherclawv1.GuardrailScopeKind_GUARDRAIL_SCOPE_KIND_ORG},
		Name:  "again", Bounds: []byte(`{}`),
	})
	wantCode(t, "a second org guardrail", err, connect.CodeAlreadyExists)
	envID := env.GetEnvelope().GetId()

	expire := timestamppb.New(time.Now().Add(48 * time.Hour))
	issued, err := grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, TaskRef: "refunds", ExpireTime: expire,
		Bounds: []byte(bounds), Limits: []byte(`{"budgets": [{"id": "daily", "grouping": "task", "operations": ["payments.refund.create"], "currency": "USD", "limit": "100.00", "period": "day"}]}`),
		Delegation: &pantherclawv1.GrantDelegation{Depth: 1, MaxChildren: 2},
	})
	if err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}
	g := issued.GetGrant()
	if g.GetRevision() != 1 || g.GetState() != pantherclawv1.GrantState_GRANT_STATE_ACTIVE || g.GetGrantor().GetId() != admin.String() ||
		g.GetEnvironmentId() != o.env.String() || !strings.Contains(g.GetBasis(), "grant.issue") {
		t.Fatalf("IssueGrant = %v", g)
	}

	// Outside the guardrail: a longer life than the org allows, an operation
	// it does not cover, and malformed documents are refused.
	_, err = grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: timestamppb.New(time.Now().Add(96 * time.Hour)), Bounds: []byte(bounds),
	})
	wantCode(t, "a grant outliving the guardrail", err, connect.CodeFailedPrecondition)
	_, err = grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: expire, Bounds: []byte(`{"operations": ["github.push"]}`),
	})
	wantCode(t, "an operation outside the guardrail", err, connect.CodeFailedPrecondition)
	_, err = grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: expire, Bounds: []byte(`{"operations": null}`),
	})
	wantCode(t, "null in bounds", err, connect.CodeInvalidArgument)
	_, err = grants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: expire, Bounds: []byte(bounds),
		Requirements: []byte(`[{"operations": ["payments.refund.create"], "approval": {"role": "approver", "count": 1}, "reason": "HELD", "extra": 1}]`),
	})
	wantCode(t, "unknown member in requirements", err, connect.CodeInvalidArgument)

	// Revise: narrowing from a stale revision is refused, from the current one
	// it is stored as revision 2.
	_, err = grants.ReviseGrant(ctx, &pantherclawv1.ReviseGrantRequest{Id: g.GetId(), Revision: 2, Bounds: []byte(bounds)})
	wantCode(t, "revise a stale revision", err, connect.CodeAborted)
	revised, err := grants.ReviseGrant(ctx, &pantherclawv1.ReviseGrantRequest{
		Id: g.GetId(), Revision: 1, TaskRef: "refunds", Bounds: []byte(`{"operations": ["payments.refund.create"], "targets": {"payments.charge": {"prefixes": ["ch_1"]}}}`),
		Limits: g.GetLimits(), Delegation: g.GetDelegation(),
	})
	if err != nil || revised.GetGrant().GetRevision() != 2 || revised.GetWidens() {
		t.Fatalf("ReviseGrant = %v, %v", revised, err)
	}

	got, err := grants.GetGrant(ctx, &pantherclawv1.GetGrantRequest{Id: g.GetId()})
	if err != nil || got.GetGrant().GetRevision() != 2 || len(got.GetLineage()) != 0 || len(got.GetGuardrails()) != 1 ||
		got.GetGuardrails()[0].GetEnvelopeId() != envID || !strings.Contains(string(got.GetEffectiveBounds()), `"ch_1"`) ||
		got.GetGrant().GetCreateTime() == nil {
		t.Fatalf("GetGrant = %v, %v", got, err)
	}
	state, err := grants.GetBudgetState(ctx, &pantherclawv1.GetBudgetStateRequest{GrantId: g.GetId()})
	if err != nil || len(state.GetAccounts()) != 0 {
		t.Fatalf("GetBudgetState before any action = %v, %v", state, err)
	}
	list, err := grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{AgentId: new(o.agent.String())})
	if err != nil || len(list.GetGrants()) != 1 || list.GetGrants()[0].GetId() != g.GetId() {
		t.Fatalf("ListGrants = %v, %v", list, err)
	}

	// Guardrails: revise narrows (not a widening), read a past revision, list.
	rev, err := guardrails.ReviseEnvelope(ctx, &pantherclawv1.ReviseEnvelopeRequest{
		Id: envID, Revision: 1, Name: "org", Bounds: []byte(`{"operations": ["payments.refund.*"]}`),
		Settings: &pantherclawv1.GuardrailSettings{MaxRootLifetime: durationpb.New(72 * time.Hour)},
	})
	if err != nil || rev.GetEnvelope().GetRevision() != 2 || rev.GetWidens() {
		t.Fatalf("ReviseEnvelope = %v, %v", rev, err)
	}
	old, err := guardrails.GetEnvelope(ctx, &pantherclawv1.GetEnvelopeRequest{Id: envID, Revision: new(int32(1))})
	if err != nil || old.GetEnvelope().GetRevision() != 1 || !strings.Contains(string(old.GetEnvelope().GetBounds()), `"payments.*"`) {
		t.Fatalf("GetEnvelope revision 1 = %v, %v", old, err)
	}
	envs, err := guardrails.ListEnvelopes(ctx, &pantherclawv1.ListEnvelopesRequest{})
	if err != nil || len(envs.GetEnvelopes()) != 1 || envs.GetEnvelopes()[0].GetRevision() != 2 {
		t.Fatalf("ListEnvelopes = %v, %v", envs, err)
	}

	// HR-161: a service account cannot issue grants or change guardrails,
	// even with the roles that allow it.
	saGrants, saGuardrails := s.clients(s.apiKey(t, o.org, []string{"grant.issue", "grant.read", "guardrails.manage", "guardrails.read"}, td.RoleGrantIssuer, td.RolePolicyPublisher))
	_, err = saGrants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: expire, Bounds: []byte(bounds),
	})
	wantCode(t, "a service account issues a grant", err, connect.CodePermissionDenied)
	_, err = saGuardrails.ReviseEnvelope(ctx, &pantherclawv1.ReviseEnvelopeRequest{
		Id: envID, Revision: 2, Name: "org", Bounds: []byte(`{}`),
	})
	wantCode(t, "a service account changes a guardrail", err, connect.CodePermissionDenied)

	// A viewer reads nothing; another org sees neither the grant nor the
	// guardrail.
	_, viewerTok := s.login(t, o.org, "viewer", td.RoleViewer)
	viewerGrants, _ := s.clients(viewerTok)
	_, err = viewerGrants.IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: o.agent.String(), Principal: principal, ExpireTime: expire, Bounds: []byte(bounds),
	})
	wantCode(t, "a viewer issues a grant", err, connect.CodePermissionDenied)
	other := seed(t, s)
	_, otherTok := s.login(t, other.org, "eve", td.RoleGrantIssuer, td.RolePolicyPublisher)
	otherGrants, otherGuardrails := s.clients(otherTok)
	_, err = otherGrants.GetGrant(ctx, &pantherclawv1.GetGrantRequest{Id: g.GetId()})
	wantCode(t, "another org reads the grant", err, connect.CodeNotFound)
	_, err = otherGrants.RevokeGrant(ctx, &pantherclawv1.RevokeGrantRequest{Id: g.GetId(), Reason: "mine"})
	wantCode(t, "another org revokes the grant", err, connect.CodeNotFound)
	_, err = otherGuardrails.GetEnvelope(ctx, &pantherclawv1.GetEnvelopeRequest{Id: envID})
	wantCode(t, "another org reads the guardrail", err, connect.CodeNotFound)

	revoked, err := grants.RevokeGrant(ctx, &pantherclawv1.RevokeGrantRequest{Id: g.GetId(), Reason: "done"})
	if err != nil || revoked.GetRevoked() != 1 {
		t.Fatalf("RevokeGrant = %v, %v", revoked, err)
	}
	list, err = grants.ListGrants(ctx, &pantherclawv1.ListGrantsRequest{State: pantherclawv1.GrantState_GRANT_STATE_ACTIVE})
	if err != nil || len(list.GetGrants()) != 0 {
		t.Fatalf("ListGrants active after revocation = %v, %v", list, err)
	}
}
