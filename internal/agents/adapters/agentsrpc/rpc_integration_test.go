// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package agentsrpc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	"github.com/katocxl/pantherclaw/internal/agents/adapters/agentsrpc"
	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/waitlist/adapters/waitlistrpc"
	wapp "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

type business struct{}

func (business) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

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
	s, err := rpc.NewServer(rpc.Options{Authenticate: rpcauth.New(authn, perms, nil)})
	if err != nil {
		t.Fatal(err)
	}
	pantherclawv1connect.RegisterAgentServiceHandler(s, agentsrpc.NewAgents(aapp.NewInventory(pool, business{})).WithRestorations(&approvals.Service{Pool: pool}))
	pantherclawv1connect.RegisterWaitlistServiceHandler(s, waitlistrpc.NewWaitlist(wapp.NewReader(pool)))
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

// login creates a user with role at org scope and returns its id and a
// bearer token.
func (s *stack) login(t *testing.T, org ids.OrgID, subject string, role td.RoleName) (ids.UUID, string) {
	t.Helper()
	user, session := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", org, user, subject)
	s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
		VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(role), user)
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

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) clients(tok string) (pantherclawv1connect.AgentServiceClient, pantherclawv1connect.WaitlistServiceClient) {
	tr := connecthttp.NewTransport(&http.Client{Transport: bearer{tok}}, s.url)
	return pantherclawv1connect.NewAgentServiceClient(connect.NewClient(tr)), pantherclawv1connect.NewWaitlistServiceClient(connect.NewClient(tr))
}

func wantCode(t *testing.T, what string, err error, want connect.Code) {
	t.Helper()
	if connect.CodeOf(err) != want {
		t.Errorf("%s: %v, want %s", what, err, want)
	}
}

func TestIntRPCAgentsAndWaitlist(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	team, env := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", org, team)
	s.exec(t, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", org, env, team)
	owner, ownerTok := s.login(t, org, "owner", td.RoleAgentOwner)
	_, viewerTok := s.login(t, org, "viewer", td.RoleViewer)
	agents, waitlist := s.clients(ownerTok)

	created, err := agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
		Name: "Claude Code, engineering", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
		ExecutionContext: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	})
	if err != nil || created.GetAgent().GetState() != pantherclawv1.AgentState_AGENT_STATE_CLAIMED {
		t.Fatalf("CreateAgent = %v, %v", created, err)
	}
	id := created.GetAgent().GetId()
	got, err := agents.GetAgent(ctx, &pantherclawv1.GetAgentRequest{Id: id})
	if err != nil || got.GetSummary().GetActivity() != pantherclawv1.ActivityStatus_ACTIVITY_STATUS_NO_INSTANCES ||
		got.GetSummary().GetNextAction() == "" {
		t.Fatalf("GetAgent = %v, %v", got, err)
	}
	list, err := agents.ListAgents(ctx, &pantherclawv1.ListAgentsRequest{
		States: []pantherclawv1.AgentState{pantherclawv1.AgentState_AGENT_STATE_CLAIMED},
	})
	if err != nil || len(list.GetAgents()) != 1 || list.GetOrgHasNoAgents() {
		t.Fatalf("ListAgents = %v, %v", list, err)
	}

	// A discovered agent with an open ADMISSION entry: claim it through the API.
	disc := ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.agents (org_id, id, name, state, created_by) VALUES ($1, $2, 'discovered', 'DISCOVERED', 'system')", org, disc)
	s.exec(t, org, `INSERT INTO pc.waitlist_entries (org_id, id, kind, subject_type, subject_id, agent_id, deadline_at, evidence)
		VALUES ($1, $2, 'ADMISSION', 'agent', $3, $3, now() + interval '7 days',
		'{"trusted":{"key_thumbprint":"abc"},"untrusted":{"user_agent":"curl/8"}}')`, org, ids.NewV7(), disc)
	entries, err := waitlist.ListWaitlistEntries(ctx, &pantherclawv1.ListWaitlistEntriesRequest{})
	if err != nil || len(entries.GetEntries()) != 1 || entries.GetEntries()[0].GetUntrustedEvidence()["user_agent"] != "curl/8" ||
		entries.GetEntries()[0].GetEvidence()["key_thumbprint"] != "abc" {
		t.Fatalf("ListWaitlistEntries = %v, %v", entries, err)
	}
	if _, err := agents.ClaimAgent(ctx, &pantherclawv1.ClaimAgentRequest{
		Id: disc.String(), Target: &pantherclawv1.ClaimAgentRequest_MergeIntoAgentId{MergeIntoAgentId: id}, Reason: "same agent",
	}); err != nil {
		t.Fatal(err)
	}
	entry, err := waitlist.GetWaitlistEntry(ctx, &pantherclawv1.GetWaitlistEntryRequest{Id: entries.GetEntries()[0].GetId()})
	if err != nil || entry.GetEntry().GetState() != pantherclawv1.WaitlistState_WAITLIST_STATE_APPROVED || entry.GetEntry().GetDecideTime() == nil {
		t.Fatalf("GetWaitlistEntry = %v, %v", entry, err)
	}
	history, err := agents.ListAgentChanges(ctx, &pantherclawv1.ListAgentChangesRequest{AgentId: id})
	if err != nil || len(history.GetChanges()) != 2 {
		t.Fatalf("ListAgentChanges = %v, %v", history, err)
	}

	// Validation and permissions happen before any change.
	_, err = agents.SuspendAgent(ctx, &pantherclawv1.SuspendAgentRequest{Id: id})
	wantCode(t, "suspend without a reason", err, connect.CodeInvalidArgument)
	_, err = agents.GetAgent(ctx, &pantherclawv1.GetAgentRequest{Id: "not-a-uuid"})
	wantCode(t, "invalid id", err, connect.CodeInvalidArgument)
	_, err = agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
		Name: "x", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
	})
	wantCode(t, "no execution context", err, connect.CodeInvalidArgument)
	viewerAgents, viewerWaitlist := s.clients(viewerTok)
	_, err = viewerAgents.GetAgent(ctx, &pantherclawv1.GetAgentRequest{Id: id})
	wantCode(t, "viewer reads an agent", err, connect.CodePermissionDenied)
	_, err = viewerWaitlist.ListWaitlistEntries(ctx, &pantherclawv1.ListWaitlistEntriesRequest{})
	wantCode(t, "viewer reads the waitlist", err, connect.CodePermissionDenied)
	if _, err := agents.RetireAgent(ctx, &pantherclawv1.RetireAgentRequest{Id: id, Reason: "replaced"}); err != nil {
		t.Fatal(err)
	}
}

// TestHR176_ARestorationIsRequestedThroughTheAPI (decision 11): the owner
// asks for a suspended agent to be restored and gets the approval request,
// its waitlist entry and the deadline; asking again returns the same one.
func TestHR176_ARestorationIsRequestedThroughTheAPI(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	team, env := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", org, team)
	s.exec(t, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", org, env, team)
	owner, ownerTok := s.login(t, org, "owner", td.RoleAgentOwner)
	agents, _ := s.clients(ownerTok)
	created, err := agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
		Name: "refunds", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
		ExecutionContext: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetAgent().GetId()
	_, err = agents.RequestAgentRestoration(ctx, &pantherclawv1.RequestAgentRestorationRequest{Id: id, Reason: "fixed"})
	wantCode(t, "an agent that is not suspended", err, connect.CodeFailedPrecondition)
	if _, err := agents.SuspendAgent(ctx, &pantherclawv1.SuspendAgentRequest{Id: id, Reason: "leaked key"}); err != nil {
		t.Fatal(err)
	}
	r, err := agents.RequestAgentRestoration(ctx, &pantherclawv1.RequestAgentRestorationRequest{Id: id, Reason: "the key was rotated"})
	if err != nil || r.GetApprovalRequestId() == "" || r.GetWaitlistEntryId() == "" || r.GetDeadlineTime() == nil {
		t.Fatalf("restoration: %v, %v", r, err)
	}
	again, err := agents.RequestAgentRestoration(ctx, &pantherclawv1.RequestAgentRestorationRequest{Id: id, Reason: "again"})
	if err != nil || again.GetApprovalRequestId() != r.GetApprovalRequestId() || again.GetWaitlistEntryId() != r.GetWaitlistEntryId() {
		t.Fatalf("again: %v, %v", again, err)
	}
}
