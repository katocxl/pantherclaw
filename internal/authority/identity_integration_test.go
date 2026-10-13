// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package authority_test

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect/v2"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/authority/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	pcIssuer = "https://pc.example.test"
	gwURL    = "https://gw.example.test/v1/refunds"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

// workload is an admitted instance with its key and a workload token.
type workload struct {
	key   ed25519.PrivateKey
	inst  pap.Instance
	token string
}

type idFixture = fixture

func setupIdentity(t *testing.T) fixture { return setup(t, "1000.00", 0, time.Minute) }

// setup is setupBase with workload identity: a verified agent with an
// admitted instance (wl) and a run bound to it and to the agent's grant.
func setup(t *testing.T, limit string, maxCount int, ttl time.Duration) fixture {
	t.Helper()
	f := setupBase(t, limit, maxCount, ttl)
	f.team, f.env, f.owner = ids.NewV7(), ids.NewV7(), ids.NewV7()
	k, _ := keys.GenerateSigningKey(keys.PurposeWorkloadTokens)
	if err := f.reg.Put(k); err != nil {
		t.Fatal(err)
	}
	f.ident = iapp.New(f.pool, f.reg, pcIssuer, clock.System{})
	f.runs = runsapp.New(f.pool).WithGrants(&grantspg.Store{Pool: f.pool})
	f.inv = aapp.NewInventory(f.pool, unlimited{})
	f.svc.WithWorkloads(f.ident, f.runs)
	f.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", f.gw.Org, f.team)
	f.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", f.gw.Org, f.env, f.team)
	f.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", f.gw.Org, f.owner)
	agent := f.agent(t)
	f.wl = f.admitted(t, agent)
	f.run = f.startRun(t, agent, &f.wl.inst.Instance)
	f.grant = f.grantFor(t, agent)
	return f
}

func (f idFixture) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (f idFixture) count(t *testing.T, sql string) int {
	t.Helper()
	var n int
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, f.gw.Org).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f idFixture) ownerCtx() context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: f.gw.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: f.owner},
		Bindings: []td.Binding{{Role: td.RoleAgentOwner, Scope: td.Scope{Type: td.ScopeTeam, ID: f.team}}},
	}})
}

// agent creates a verified agent.
func (f idFixture) agent(t *testing.T) ids.UUID {
	t.Helper()
	a, err := f.inv.Create(f.ownerCtx(), adomain.Details{
		Name: "refunder", TeamID: f.team, EnvironmentID: f.env, OwnerUserID: f.owner, Context: adomain.ContextService,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.pool.InTenantTx(context.Background(), f.gw.Org, func(ctx context.Context, tx db.TenantTx) error {
		return aapp.MarkVerified(ctx, dbq.New(tx), f.gw.Org, a.ID, adomain.System)
	}); err != nil {
		t.Fatal(err)
	}
	return a.ID
}

// admitted inserts an admitted instance of agent and issues its token.
func (f idFixture) admitted(t *testing.T, agent ids.UUID) workload {
	t.Helper()
	pub, key, _ := ed25519.GenerateKey(nil)
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	id := ids.NewV7()
	f.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via)
		VALUES ($1, $2, $3, $4, $5, 'ADMITTED', 'discovery')`, f.gw.Org, id, agent, jws.Thumbprint(pub), jwk)
	inst := pap.Instance{Org: f.gw.Org, Agent: agent, Instance: id}
	signer, err := f.reg.Signer(keys.PurposeWorkloadTokens)
	if err != nil {
		t.Fatal(err)
	}
	tok, _, err := pap.Issue(signer, pcIssuer, pap.Token{Instance: inst, Environment: f.env, JKT: jws.Thumbprint(pub), Level: 1}, time.Now(), time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	return workload{key: key, inst: inst, token: tok}
}

var refundBody = []byte(`{"charge":"ch_1","amount":"30.00","currency":"USD"}`)

// creds signs a proof for the request with wl's key and token.
func (f idFixture) creds(t *testing.T, wl workload, token string) *authority.Credentials {
	t.Helper()
	n, err := f.ident.Nonce(context.Background(), f.gw.Org)
	if err != nil {
		t.Fatal(err)
	}
	return f.credsWith(t, wl, token, n)
}

// credsWith is creds with a known nonce.
func (f fixture) credsWith(t *testing.T, wl workload, token, nonce string) *authority.Credentials {
	t.Helper()
	proof, err := pap.NewProof(wl.key, pap.ProofParams{Method: "POST", URL: gwURL, Body: refundBody, Token: token, Nonce: nonce, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	return &authority.Credentials{Token: token, Proof: proof, BodySHA256: sha256.Sum256(refundBody), Method: "POST", URL: gwURL}
}

func (f idFixture) authorizeAs(t *testing.T, wl workload, run ids.UUID, c *authority.Credentials) authority.Result {
	t.Helper()
	raw := f.actionAs(t, "30.00", run, ids.NewV7(), f.env.String(), wl.inst.Instance.String())
	res, err := f.svc.Authorize(context.Background(), f.gw, raw, c)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// startRun starts a run of agent bound to the agent's grant.
func (f idFixture) startRun(t *testing.T, agent ids.UUID, instance *ids.UUID) ids.UUID {
	t.Helper()
	g := f.grantFor(t, agent).UUID()
	r, err := f.runs.StartRun(f.ownerCtx(), runsapp.StartInput{AgentID: agent, InstanceID: instance, GrantID: &g})
	if err != nil {
		t.Fatal(err)
	}
	return r.ID
}

func wantDecision(t *testing.T, what string, res authority.Result, d domain.Decision, code, detail string) {
	t.Helper()
	if res.Decision != d || len(res.Reasons) == 0 || res.Reasons[0].Code != code || (detail != "" && res.Reasons[0].Detail != detail) {
		t.Errorf("%s: %s %+v, want %s %s %s", what, res.Decision, res.Reasons, d, code, detail)
	}
}

// TestHR021_AuthorizeReverifiesWorkloadCredentials: the Authority verifies
// the forwarded token and proof itself; anything unverifiable is
// CANNOT_AUTHORIZE and records no transaction.
func TestHR021_AuthorizeReverifiesWorkloadCredentials(t *testing.T) {
	f := setupIdentity(t)
	agent := f.agent(t)
	wl := f.admitted(t, agent)
	run := f.startRun(t, agent, &wl.inst.Instance)
	ok := f.creds(t, wl, wl.token)
	res := f.authorizeAs(t, wl, run, ok)
	if res.Decision != domain.Allow || res.Nonce == "" || res.Permit == "" {
		t.Fatalf("verified workload: %+v", res)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.agents WHERE org_id = $1 AND state = 'OBSERVED'"); n != 1 {
		t.Errorf("the first verified request did not mark the agent OBSERVED")
	}
	tampered := f.creds(t, wl, wl.token)
	tampered.BodySHA256[0] ^= 1
	other := f.admitted(t, agent)
	for name, tc := range map[string]struct {
		c    *authority.Credentials
		code pap.Code
	}{
		"no credentials":      {nil, pap.CodeInvalidToken},
		"replayed proof":      {ok, pap.CodeProofReplay},
		"changed body":        {tampered, pap.CodeBodyHashMismatch},
		"key-only proof":      {f.creds(t, wl, ""), pap.CodeInvalidToken},
		"another key's token": {f.creds(t, wl, other.token), pap.CodeKeyMismatch},
	} {
		wantDecision(t, name, f.authorizeAs(t, wl, run, tc.c), domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(tc.code))
	}
	f.exec(t, "UPDATE pc.agent_instances SET state = 'REVOKED', decided_by = 'test', decided_at = now() WHERE org_id = $1 AND id = $2", f.gw.Org, wl.inst.Instance)
	wantDecision(t, "revoked instance", f.authorizeAs(t, wl, run, f.creds(t, wl, wl.token)),
		domain.CannotAuthorize, domain.ReasonIdentityUnverified, string(pap.CodeInstanceNotAdmitted))
	// The gateway fetches the nonce it serves to workloads (HR-091).
	got, err := authority.NewHandler(f.svc).GetNonce(authority.WithGateway(context.Background(), f.gw), &pantherclawv1.GetNonceRequest{})
	if err != nil || got.GetNonce() == "" || !got.GetExpireTime().AsTime().After(time.Now()) {
		t.Errorf("GetNonce = %v, %v", got, err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1"); n != 1 {
		t.Errorf("transactions %d, want only the allowed one", n)
	}
}

// TestHR022_AuthorizeChecksTheRunBinding: an unknown run, another agent's
// run, a run bound to another instance, an ended run and an action naming
// another instance are DENY and record nothing; a suspended agent is DENY.
func TestHR022_AuthorizeChecksTheRunBinding(t *testing.T) {
	f := setupIdentity(t)
	agent, otherAgent := f.agent(t), f.agent(t)
	first, second := f.admitted(t, agent), f.admitted(t, agent)
	unbound := f.startRun(t, agent, nil)
	if res := f.authorizeAs(t, first, unbound, f.creds(t, first, first.token)); res.Decision != domain.Allow {
		t.Fatalf("first use: %+v", res)
	}
	deny := func(what string, wl workload, run ids.UUID) {
		t.Helper()
		wantDecision(t, what, f.authorizeAs(t, wl, run, f.creds(t, wl, wl.token)), domain.Deny, domain.ReasonRunMismatch, "")
	}
	deny("run bound to another instance", second, unbound)
	deny("client-chosen run id", first, ids.NewV7())
	deny("another agent's run", first, f.startRun(t, otherAgent, nil))
	ended := f.startRun(t, agent, &first.inst.Instance)
	if _, err := f.runs.EndRun(f.ownerCtx(), ended, "done"); err != nil {
		t.Fatal(err)
	}
	deny("ended run", first, ended)
	raw := f.actionAs(t, "30.00", unbound, ids.NewV7(), f.env.String(), second.inst.Instance.String())
	res, err := f.svc.Authorize(context.Background(), f.gw, raw, f.creds(t, first, first.token))
	if err != nil {
		t.Fatal(err)
	}
	wantDecision(t, "action naming another instance", res, domain.Deny, domain.ReasonIdentityMismatch, "")
	if _, err := f.inv.Suspend(f.ownerCtx(), agent, "investigating"); err != nil {
		t.Fatal(err)
	}
	wantDecision(t, "suspended agent", f.authorizeAs(t, first, unbound, f.creds(t, first, first.token)),
		domain.Deny, domain.ReasonAgentUnusable, "")
	if n := f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1"); n != 1 {
		t.Errorf("transactions %d, want only the allowed one", n)
	}
}

// TestHR022_FirstUseBindingIsRaceSafe: instances racing to use an unbound
// run bind exactly one of them.
func TestHR022_FirstUseBindingIsRaceSafe(t *testing.T) {
	f := setupIdentity(t)
	agent := f.agent(t)
	a, b := f.admitted(t, agent), f.admitted(t, agent)
	run := f.startRun(t, agent, nil)
	var mu sync.Mutex
	won := map[ids.UUID]int{}
	var wg sync.WaitGroup
	for i := range 20 {
		wl := a
		if i%2 == 1 {
			wl = b
		}
		wg.Go(func() {
			if _, err := f.runs.Bind(context.Background(), f.gw.Org, run, agent, wl.inst.Instance); err == nil {
				mu.Lock()
				won[wl.inst.Instance]++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if len(won) != 1 {
		t.Fatalf("instances that may use the run: %v, want exactly one", won)
	}
}

// TestHR148_ReportUnknownWorkloadVerifiesTheReport: the Authority records a
// gateway's report only when its key-only proof verifies; the reported
// request gains nothing.
func TestHR148_ReportUnknownWorkloadVerifiesTheReport(t *testing.T) {
	f := setupIdentity(t)
	h := authority.NewHandler(f.svc)
	ctx := authority.WithGateway(context.Background(), f.gw)
	_, key, _ := ed25519.GenerateKey(nil)
	stranger := workload{key: key}
	report := func(c *authority.Credentials) (*pantherclawv1.ReportUnknownWorkloadResponse, error) {
		return h.ReportUnknownWorkload(ctx, &pantherclawv1.ReportUnknownWorkloadRequest{
			Workload: &pantherclawv1.WorkloadCredentials{
				WorkloadToken: c.Token, Proof: c.Proof, BodySha256: c.BodySHA256[:], Htm: c.Method, Htu: c.URL,
			},
			Route: "payments-refund", UserAgent: "curl/8",
		})
	}
	got, err := report(f.creds(t, stranger, ""))
	if err != nil || got.GetDiscoveryId() == "" || got.GetNonce() == "" {
		t.Fatalf("report: %v, %v", got, err)
	}
	replayed := f.creds(t, stranger, "")
	if _, err := report(replayed); err != nil {
		t.Fatal(err)
	}
	if _, err := report(replayed); err == nil {
		t.Error("a replayed report was accepted")
	}
	agent := f.agent(t)
	wl := f.admitted(t, agent)
	if _, err := report(f.creds(t, wl, wl.token)); err == nil {
		t.Error("a report with a workload token was accepted")
	}
	if n := f.count(t, "SELECT count(*) FROM pc.discoveries WHERE org_id = $1"); n != 1 {
		t.Errorf("discoveries %d, want 1", n)
	}
}

// TestHR021_VerifyWorkloadChecksCredentialsAndDecidesNothing: a request
// that decides nothing (an MCP tools/list) is still verified by the
// Authority. An admitted instance verifies with its environment; a
// replayed proof, a key-only proof, missing credentials and a suspended
// agent do not, with their codes; nothing is decided or recorded.
func TestHR021_VerifyWorkloadChecksCredentialsAndDecidesNothing(t *testing.T) {
	f := setupIdentity(t)
	agent := f.agent(t)
	wl := f.admitted(t, agent)
	h := authority.NewHandler(f.svc)
	ctx := authority.WithGateway(context.Background(), f.gw)
	verify := func(c *authority.Credentials) *pantherclawv1.VerifyWorkloadResponse {
		t.Helper()
		var w *pantherclawv1.WorkloadCredentials
		if c != nil {
			w = &pantherclawv1.WorkloadCredentials{WorkloadToken: c.Token, Proof: c.Proof, BodySha256: c.BodySHA256[:], Htm: c.Method, Htu: c.URL}
		}
		res, err := h.VerifyWorkload(ctx, &pantherclawv1.VerifyWorkloadRequest{Workload: w})
		if err != nil {
			t.Fatal(err)
		}
		return res
	}
	ok := f.creds(t, wl, wl.token)
	if r := verify(ok); !r.GetVerified() || r.GetInstanceId() != wl.inst.Instance.String() || r.GetEnvironmentId() == "" || r.GetNonce() == "" {
		t.Fatalf("admitted instance: %+v", r)
	}
	for name, tc := range map[string]struct {
		c    *authority.Credentials
		code string
	}{
		"replayed proof": {ok, string(pap.CodeProofReplay)},
		"key-only proof": {f.creds(t, wl, ""), string(pap.CodeInvalidToken)},
		"no credentials": {nil, string(pap.CodeInvalidToken)},
	} {
		if r := verify(tc.c); r.GetVerified() || r.GetErrorCode() != tc.code || r.GetNonce() == "" {
			t.Errorf("%s: %+v", name, r)
		}
	}
	f.exec(t, "UPDATE pc.agents SET suspended_from = state, state = 'SUSPENDED' WHERE org_id = $1 AND id = $2", f.gw.Org, agent)
	if r := verify(f.creds(t, wl, wl.token)); r.GetVerified() || r.GetErrorCode() != "agent_unusable" {
		t.Errorf("suspended agent: %+v", r)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.transactions WHERE org_id = $1"); n != 0 {
		t.Errorf("verifying recorded %d transactions", n)
	}
}

// TestHR022_VerifyWorkloadChecksTheRun: a request naming a run (an MCP
// session's initialize) verifies only for a run the instance may use, as
// an action would, and returns the key's thumbprint and the run's expiry;
// an unknown run, another agent's run, a run bound to another instance and
// an ended run are run_mismatch; a malformed run id is refused.
func TestHR022_VerifyWorkloadChecksTheRun(t *testing.T) {
	f := setupIdentity(t)
	agent, otherAgent := f.agent(t), f.agent(t)
	first, second := f.admitted(t, agent), f.admitted(t, agent)
	h := authority.NewHandler(f.svc)
	ctx := authority.WithGateway(context.Background(), f.gw)
	verify := func(wl workload, run string) (*pantherclawv1.VerifyWorkloadResponse, error) {
		t.Helper()
		c := f.creds(t, wl, wl.token)
		w := &pantherclawv1.WorkloadCredentials{WorkloadToken: c.Token, Proof: c.Proof, BodySha256: c.BodySHA256[:], Htm: c.Method, Htu: c.URL}
		return h.VerifyWorkload(ctx, &pantherclawv1.VerifyWorkloadRequest{Workload: w, RunId: run})
	}
	run := f.startRun(t, agent, nil)
	r, err := verify(first, run.String())
	jkt := jws.Thumbprint(first.key.Public().(ed25519.PublicKey))
	if err != nil || !r.GetVerified() || r.GetJkt() != jkt || r.GetRunExpiresAt() == nil || !r.GetRunExpiresAt().AsTime().After(time.Now()) {
		t.Fatalf("own run: %+v %v", r, err)
	}
	if r, err := verify(first, ""); err != nil || !r.GetVerified() || r.GetRunExpiresAt() != nil {
		t.Fatalf("no run: %+v %v", r, err)
	}
	ended := f.startRun(t, agent, &first.inst.Instance)
	if _, err := f.runs.EndRun(f.ownerCtx(), ended, "done"); err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		wl  workload
		run ids.UUID
	}{
		"run bound to another instance": {second, run},
		"unknown run":                   {first, ids.NewV7()},
		"another agent's run":           {first, f.startRun(t, otherAgent, nil)},
		"ended run":                     {first, ended},
	} {
		if r, err := verify(tc.wl, tc.run.String()); err != nil || r.GetVerified() || r.GetErrorCode() != string(pap.CodeRunMismatch) ||
			r.GetJkt() != "" || r.GetRunExpiresAt() != nil {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	if _, err := verify(first, "not-a-run"); connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("malformed run id: %v", err)
	}
}

// TestHR200_RecordToolObservationVerifiesTheWorkloadFirst: an agent SDK's
// unmapped tool call is recorded only for a workload the Authority
// verifies in a run it may use, against the verified instance, never one
// the gateway names (HR-021, HR-022). A proof that does not verify, a
// replayed proof, another agent's run, a connection another gateway serves
// and a suspended agent are answers with their codes and record nothing; a
// nil or malformed run id is refused, and without a recorder the call
// fails.
func TestHR200_RecordToolObservationVerifiesTheWorkloadFirst(t *testing.T) {
	f := setupIdentity(t)
	ctx := authority.WithGateway(context.Background(), f.gw)
	digest := sha256.Sum256([]byte(`{"command":"ls"}`))
	observe := func(h *authority.Handler, c *authority.Credentials, run, conn string) (*pantherclawv1.RecordToolObservationResponse, error) {
		t.Helper()
		var w *pantherclawv1.WorkloadCredentials
		if c != nil {
			w = &pantherclawv1.WorkloadCredentials{WorkloadToken: c.Token, Proof: c.Proof, BodySha256: c.BodySHA256[:], Htm: c.Method, Htu: c.URL}
		}
		return h.RecordToolObservation(ctx, &pantherclawv1.RecordToolObservationRequest{
			Workload: w, RunId: run, ConnectionId: conn, Tool: "Bash", InputSha256: digest[:],
		})
	}
	recorded := func() int { return f.count(t, "SELECT count(*) FROM pc.tool_observations WHERE org_id = $1") }
	if _, err := observe(authority.NewHandler(f.svc), f.creds(t, f.wl, f.wl.token), f.run.String(), f.conn.String()); err == nil {
		t.Fatal("without a recorder: no error")
	}

	f.svc.WithToolObservations(capp.New(f.pool, nil, "", ""))
	h := authority.NewHandler(f.svc)
	ok := f.creds(t, f.wl, f.wl.token)
	r, err := observe(h, ok, f.run.String(), f.conn.String())
	if err != nil || !r.GetVerified() || r.GetInstanceId() != f.wl.inst.Instance.String() || r.GetObservationId() == "" || r.GetNonce() == "" {
		t.Fatalf("verified workload: %+v %v", r, err)
	}
	if n := f.count(t, "SELECT count(*) FROM pc.tool_observations WHERE org_id = $1 AND id = '"+r.GetObservationId()+
		"' AND instance_id = '"+f.wl.inst.Instance.String()+"' AND run_id = '"+f.run.String()+"' AND tool = 'Bash'"); n != 1 {
		t.Fatalf("the stored observation is not the verified instance's: %d", n)
	}

	elsewhere, served := ids.NewV7(), ids.NewV7()
	f.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'other-edge', 'test')", f.gw.Org, elsewhere)
	f.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by) VALUES ($1, $2, 'elsewhere', 'http', $3, 'pc.mock-payments', 'https://payments.example.test', 'none',
		'enforce', 'test', 'test')`, f.gw.Org, served, elsewhere)
	for name, tc := range map[string]struct {
		c         *authority.Credentials
		run, conn ids.UUID
		code      string
	}{
		"replayed proof":            {ok, f.run, f.conn, string(pap.CodeProofReplay)},
		"key-only proof":            {f.creds(t, f.wl, ""), f.run, f.conn, string(pap.CodeInvalidToken)},
		"no credentials":            {nil, f.run, f.conn, string(pap.CodeInvalidToken)},
		"another agent's run":       {f.creds(t, f.wl, f.wl.token), f.startRun(t, f.agent(t), nil), f.conn, string(pap.CodeRunMismatch)},
		"another gateway's service": {f.creds(t, f.wl, f.wl.token), f.run, served, "connection_not_served"},
	} {
		if r, err := observe(h, tc.c, tc.run.String(), tc.conn.String()); err != nil || r.GetVerified() || r.GetErrorCode() != tc.code ||
			r.GetObservationId() != "" || r.GetNonce() == "" {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
	for name, run := range map[string]string{"nil run": ids.UUID{}.String(), "malformed run": "not-a-run"} {
		if _, err := observe(h, f.creds(t, f.wl, f.wl.token), run, f.conn.String()); connect.CodeOf(err) != connect.CodeInvalidArgument {
			t.Errorf("%s: %v", name, err)
		}
	}
	f.exec(t, "UPDATE pc.agents SET suspended_from = state, state = 'SUSPENDED' WHERE org_id = $1 AND id = $2", f.gw.Org, f.wl.inst.Agent)
	if r, err := observe(h, f.creds(t, f.wl, f.wl.token), f.run.String(), f.conn.String()); err != nil || r.GetVerified() ||
		r.GetErrorCode() != "agent_unusable" {
		t.Errorf("suspended agent: %+v %v", r, err)
	}
	if n := recorded(); n != 1 {
		t.Errorf("%d observations recorded, want only the verified one", n)
	}
}
