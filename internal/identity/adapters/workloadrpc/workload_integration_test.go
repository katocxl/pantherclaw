// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package workloadrpc_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/agents/adapters/agentsrpc"
	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	approvals "github.com/katocxl/pantherclaw/internal/approvals/app"
	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/authn/credential"
	"github.com/katocxl/pantherclaw/internal/authn/token"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/grants/adapters/grantsrpc"
	grantspg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/identityrpc"
	"github.com/katocxl/pantherclaw/internal/identity/adapters/workloadrpc"
	iapp "github.com/katocxl/pantherclaw/internal/identity/app"
	"github.com/katocxl/pantherclaw/internal/identity/issuers"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/identity/workloadclient"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/platform/rpc/protoperms"
	"github.com/katocxl/pantherclaw/internal/runs/adapters/runsrpc"
	runsapp "github.com/katocxl/pantherclaw/internal/runs/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	waitlist "github.com/katocxl/pantherclaw/internal/waitlist/app"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

type stack struct {
	pool   *db.Pool
	tokens *token.Service
	svc    *iapp.Service
	url    string
	waits  *approvals.Waits
}

func newStack(t *testing.T) *stack { return newStackAt(t, clock.System{}) }

// newStackAt runs the identity service and WorkloadService on clk (the
// database keeps its own clock for nonces).
func newStackAt(t *testing.T, clk clock.Clock) *stack {
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
	mux := http.NewServeMux()
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	tokens, err := token.New(reg, ts.URL, token.Audience)
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
	svc := iapp.New(pool, reg, ts.URL, clk)
	gstore := &grantspg.Store{Pool: pool}
	grants := &grantsapp.Service{
		Repo: gstore, Subjects: gstore, Defs: &defspg.Store{Pool: pool}, Authz: grantsapp.SubjectAuthorizer{},
		Clock: clock.System{}, Listing: gstore,
	}
	runs := runsapp.New(pool).WithGrants(gstore)
	pantherclawv1connect.RegisterRunServiceHandler(s, runsrpc.NewRuns(runs))
	pantherclawv1connect.RegisterGrantServiceHandler(s, grantsrpc.NewGrants(grants))
	pantherclawv1connect.RegisterAgentServiceHandler(s, agentsrpc.NewAgents(aapp.NewInventory(pool, unlimited{})))
	pantherclawv1connect.RegisterIdentityServiceHandler(s, identityrpc.NewIdentity(svc, nil))
	waits := approvals.NewWaits(pool, 1, 0, nil)
	wl := workloadrpc.NewWorkload(svc, runs, ts.URL, clk).WithGrants(grants).WithWaits(waits).
		WithApprovals(&approvals.Service{Pool: pool}, waitlist.NewWriter(pool))
	pantherclawv1connect.RegisterWorkloadServiceHandler(s, wl)
	inner := http.NewServeMux()
	rpc.Mount(inner, s)
	inner.HandleFunc("GET "+workloadrpc.WaitPath+"{transaction}", wl.WaitStream)
	mux.Handle("/", workloadrpc.RawBody(inner, nil))
	return &stack{pool: pool, tokens: tokens, svc: svc, url: ts.URL, waits: waits}
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

func (s *stack) login(t *testing.T, org ids.OrgID, roles ...td.RoleName) (ids.UUID, string) {
	t.Helper()
	user, session := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', $3)", org, user, user.String())
	for _, r := range roles {
		s.exec(t, org, `INSERT INTO pc.role_bindings (org_id, id, role, user_id, scope_type, created_by)
			VALUES ($1, $2, $3, $4, 'ORG', 'test')`, org, ids.NewV7(), string(r), user)
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

type bearer struct{ tok string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func (s *stack) connectClient(rt http.RoundTripper) *connect.Client {
	return connect.NewClient(connecthttp.NewTransport(&http.Client{Transport: rt}, s.url))
}

// recorder keeps the last request it sent, body included.
type recorder struct {
	base   http.RoundTripper
	header http.Header
	body   []byte
}

func (r *recorder) RoundTrip(req *http.Request) (*http.Response, error) {
	body, _ := io.ReadAll(req.Body)
	r.header, r.body = req.Header.Clone(), body
	req.Body = io.NopCloser(bytes.NewReader(body))
	return r.base.RoundTrip(req)
}

func TestIntWorkloadEnrollAdmitAndToken(t *testing.T) {
	s := newStack(t)
	ctx := context.Background()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	team, env := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", org, team)
	s.exec(t, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", org, env, team)
	owner, tok := s.login(t, org, td.RoleAgentOwner, td.RoleAgentAdmitter, td.RoleGrantIssuer)
	admin := s.connectClient(bearer{tok})
	agents := pantherclawv1connect.NewAgentServiceClient(admin)
	identity := pantherclawv1connect.NewIdentityServiceClient(admin)
	a, err := agents.CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
		Name: "coder", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
		ExecutionContext: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	})
	if err != nil {
		t.Fatal(err)
	}
	et, err := identity.CreateEnrollmentToken(ctx, &pantherclawv1.CreateEnrollmentTokenRequest{AgentId: a.GetAgent().GetId()})
	if err != nil {
		t.Fatal(err)
	}

	// The workload: its own key, a PAP/1 transport; the first call has no
	// nonce and is retried once with the one the server sends.
	pub, key, _ := ed25519.GenerateKey(nil)
	rec := &recorder{base: http.DefaultTransport}
	wt := &workloadclient.Transport{Key: key, Base: rec}
	workload := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(wt))
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	enrolled, err := workload.Enroll(ctx, &pantherclawv1.EnrollRequest{EnrollmentToken: et.GetToken(), PublicJwk: string(jwk)})
	if err != nil || enrolled.GetFingerprint() != jws.Thumbprint(pub) || wt.Nonce() == "" {
		t.Fatalf("Enroll = %v, %v (nonce %q)", enrolled, err, wt.Nonce())
	}
	if _, err := identity.AdmitInstance(ctx, &pantherclawv1.AdmitInstanceRequest{
		Id: enrolled.GetInstanceId(), Fingerprint: enrolled.GetFingerprint(),
	}); err != nil {
		t.Fatal(err)
	}
	issued, err := workload.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: enrolled.GetIdentifier()})
	if err != nil || issued.GetAttestationLevel() != 1 {
		t.Fatalf("IssueToken = %v, %v", issued, err)
	}
	v, _ := s.svc.TokenVerifier()
	if wtok, err := pap.VerifyToken(v, s.url, issued.GetWorkloadToken(), time.Now()); err != nil || wtok.JKT != jws.Thumbprint(pub) {
		t.Fatalf("workload token: %+v, %v", wtok, err)
	}

	// Raw replays of the last request (HR-090), a tampered body (HR-091), a
	// missing proof and a proof for another host are refused with PAP-Error.
	post := func(header http.Header, body []byte) (int, string) {
		req, _ := http.NewRequest(http.MethodPost, s.url+"/pantherclaw.v1.WorkloadService/IssueToken", bytes.NewReader(body))
		req.Header = header.Clone()
		resp, err := httpx.NewControlClient(httpx.ControlConfig{}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.StatusCode, resp.Header.Get("PAP-Error")
	}
	if code, e := post(rec.header, rec.body); code != http.StatusUnauthorized || e != "proof_replay" {
		t.Errorf("replayed request: %d %q", code, e)
	}
	tampered := bytes.Replace(rec.body, []byte(org.String()), []byte(ids.New[ids.Org]().String()), 1)
	if code, e := post(rec.header, tampered); code != http.StatusUnauthorized || e != "body_hash_mismatch" {
		t.Errorf("tampered body: %d %q", code, e)
	}
	noProof := rec.header.Clone()
	noProof.Del("PAP-Proof")
	if code, e := post(noProof, rec.body); code != http.StatusUnauthorized || e != "invalid_proof" {
		t.Errorf("no proof: %d %q", code, e)
	}
	proof, _ := pap.NewProof(key, pap.ProofParams{
		Method: "POST", URL: "https://evil.test/pantherclaw.v1.WorkloadService/IssueToken", Body: rec.body,
		Nonce: wt.Nonce(), Now: time.Now(),
	})
	evil := rec.header.Clone()
	evil.Set("PAP-Proof", proof)
	if code, e := post(evil, rec.body); code != http.StatusUnauthorized || e != "invalid_proof" {
		t.Errorf("proof for another host: %d %q", code, e)
	}

	// Another key cannot get a token for this instance (T-032).
	_, thief, _ := ed25519.GenerateKey(nil)
	stolen := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: thief}))
	_, err = stolen.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: enrolled.GetIdentifier()})
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "key_mismatch") {
		t.Errorf("thief's key: %v", err)
	}

	// The owner starts a run bound to the instance; the workload, proving
	// itself with its token and a proof, starts a child of it (HR-022).
	root, err := pantherclawv1connect.NewRunServiceClient(admin).StartRun(ctx, &pantherclawv1.StartRunRequest{
		AgentId: a.GetAgent().GetId(), InstanceId: proto.String(enrolled.GetInstanceId()), TaskRef: "nightly",
	})
	if err != nil {
		t.Fatal(err)
	}
	withToken := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{
		Key: key, Token: func() string { return issued.GetWorkloadToken() },
	}))
	child, err := withToken.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: root.GetRun().GetId(), AgentId: a.GetAgent().GetId()})
	if err != nil || child.GetRun().GetDepth() != 1 ||
		child.GetRun().GetPrincipalSource() != pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_PARENT_RUN {
		t.Fatalf("StartChildRun = %v, %v", child, err)
	}
	_, err = workload.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: root.GetRun().GetId(), AgentId: a.GetAgent().GetId()})
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "invalid_token") {
		t.Errorf("child run without a workload token: %v", err)
	}

	// M4: a person issues a grant that allows one level of delegation and
	// starts a run with it. The workload delegates a narrower part of it to a
	// child run, never a wider one, and only once (HR-045, HR-047, HR-161).
	runsClient := pantherclawv1connect.NewRunServiceClient(admin)
	g, err := pantherclawv1connect.NewGrantServiceClient(admin).IssueGrant(ctx, &pantherclawv1.IssueGrantRequest{
		AgentId: a.GetAgent().GetId(), Principal: &pantherclawv1.Actor{Kind: "user", Id: owner.String()},
		ExpireTime: timestamppb.New(time.Now().Add(48 * time.Hour)),
		Bounds:     []byte(`{"operations": ["payments.refund.create"], "targets": {"payments.charge": {"prefixes": ["ch_"]}}}`),
		Delegation: &pantherclawv1.GrantDelegation{Depth: 1, MaxChildren: 2},
	})
	if err != nil {
		t.Fatal(err)
	}
	granted, err := runsClient.StartRun(ctx, &pantherclawv1.StartRunRequest{
		AgentId: a.GetAgent().GetId(), InstanceId: proto.String(enrolled.GetInstanceId()), GrantId: proto.String(g.GetGrant().GetId()),
	})
	if err != nil || granted.GetRun().GetGrantId() != g.GetGrant().GetId() {
		t.Fatalf("StartRun with a grant = %v, %v", granted, err)
	}
	kid, err := withToken.StartChildRun(ctx, &pantherclawv1.StartChildRunRequest{ParentRunId: granted.GetRun().GetId(), AgentId: a.GetAgent().GetId()})
	if err != nil {
		t.Fatal(err)
	}
	delegate := func(c pantherclawv1connect.WorkloadServiceClient, bounds string) (*pantherclawv1.DelegateGrantResponse, error) {
		return c.DelegateGrant(ctx, &pantherclawv1.DelegateGrantRequest{
			RunId: granted.GetRun().GetId(), ChildRunId: kid.GetRun().GetId(), Bounds: []byte(bounds),
		})
	}
	_, err = delegate(withToken, `{"operations": ["payments.refund.create", "github.push"]}`)
	if connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a wider delegation: %v", err)
	}
	d, err := delegate(withToken, `{"targets": {"payments.charge": {"prefixes": ["ch_1"]}}}`)
	if err != nil || d.GetGrant().GetParentGrantId() != g.GetGrant().GetId() || d.GetGrant().GetDepth() != 1 ||
		d.GetGrant().GetGrantor().GetKind() != "instance" || d.GetGrant().GetGrantor().GetId() != enrolled.GetInstanceId() {
		t.Fatalf("DelegateGrant = %v, %v", d, err)
	}
	if got, err := runsClient.GetRun(ctx, &pantherclawv1.GetRunRequest{Id: kid.GetRun().GetId()}); err != nil || got.GetRun().GetGrantId() != d.GetGrant().GetId() {
		t.Fatalf("the child run's grant: %v, %v", got, err)
	}
	if _, err := delegate(withToken, `{}`); connect.CodeOf(err) != connect.CodeFailedPrecondition {
		t.Errorf("a second delegation to the same child: %v", err)
	}
	if _, err := delegate(workload, `{}`); connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "invalid_token") {
		t.Errorf("delegation without a workload token: %v", err)
	}
}

// fakeGitHub stands in for issuerkeys.Fetcher: a token whose signature
// segment is "sig" verifies.
type fakeGitHub struct{}

func (fakeGitHub) Verify(_ context.Context, tok string) ([]byte, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 || parts[2] != "sig" {
		return nil, errors.New("signature")
	}
	return base64.RawURLEncoding.DecodeString(parts[1])
}

// TestHR094_AttestedWorkloadEnrollsWithoutAnEnrollmentToken: the org comes
// from the attestation's audience, so the first call gets that org's nonce,
// and an auto-admitting entry admits the instance at L2 at once.
func TestHR094_AttestedWorkloadEnrollsWithoutAnEnrollmentToken(t *testing.T) {
	s := newStack(t)
	s.svc.WithAttestors(iapp.Attestors{GitHub: fakeGitHub{}})
	ctx := context.Background()
	org := ids.New[ids.Org]()
	s.exec(t, org, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", org)
	team, env := ids.NewV7(), ids.NewV7()
	s.exec(t, org, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", org, team)
	s.exec(t, org, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'ci', 'CI', 'DEVELOPMENT')", org, env, team)
	owner, tok := s.login(t, org, td.RoleAgentOwner)
	a, err := pantherclawv1connect.NewAgentServiceClient(s.connectClient(bearer{tok})).CreateAgent(ctx, &pantherclawv1.CreateAgentRequest{
		Name: "ci-bot", TeamId: team.String(), EnvironmentId: env.String(), OwnerUserId: owner.String(),
		ExecutionContext: pantherclawv1.ExecutionContext_EXECUTION_CONTEXT_CI,
	})
	if err != nil {
		t.Fatal(err)
	}
	agent, _ := ids.ParseUUID(a.GetAgent().GetId())
	as := func(role td.RoleName) context.Context {
		return tenancy.WithCaller(ctx, tenancy.Caller{Subject: td.Subject{
			Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
			Bindings: []td.Binding{{Role: role, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
		}})
	}
	const ref = "octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/main"
	r, err := s.svc.ProposeIssuer(as(td.RoleOrgAdmin), iapp.ProposeInput{AgentID: agent, AutoAdmit: true, Reason: "CI", Binding: iapp.Binding{
		GitHub: &issuers.GitHubBinding{RepositoryID: "123456", RepositoryOwnerID: "7890", JobType: issuers.JobWorkflow, WorkflowRefs: []string{ref}},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.svc.ActivateIssuer(as(td.RoleIdentityPublisher), r.EntryID, r.Revision, false); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss": issuers.GitHubIssuer, "aud": "pantherclaw:" + org.String(), "jti": ids.NewV7().String(),
		"repository_id": "123456", "repository_owner_id": "7890", "ref": "refs/heads/main", "ref_protected": "true",
		"event_name": "push", "workflow_ref": ref, "iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
	})
	enc := base64.RawURLEncoding.EncodeToString
	att := &pantherclawv1.Attestation{
		Kind:  pantherclawv1.AttestationKind_ATTESTATION_KIND_GITHUB_ACTIONS,
		Token: enc([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc(claims) + ".sig",
	}
	pub, key, _ := ed25519.GenerateKey(nil)
	wt := &workloadclient.Transport{Key: key}
	workload := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(wt))
	jwk, _ := json.Marshal(jws.PublicJWK(pub, ""))
	enrolled, err := workload.Enroll(ctx, &pantherclawv1.EnrollRequest{PublicJwk: string(jwk), Attestation: att})
	if err != nil || enrolled.GetState() != pantherclawv1.InstanceState_INSTANCE_STATE_ADMITTED || enrolled.GetAttestationLevel() != 2 {
		t.Fatalf("Enroll = %v, %v", enrolled, err)
	}
	issued, err := workload.IssueToken(ctx, &pantherclawv1.IssueTokenRequest{Identifier: enrolled.GetIdentifier()})
	if err != nil || issued.GetAttestationLevel() != 2 || issued.GetExpireTime().AsTime().After(now.Add(10*time.Minute)) {
		t.Fatalf("IssueToken = %v, %v", issued, err)
	}
	// The same attestation cannot enroll another key (HR-143).
	otherPub, other, _ := ed25519.GenerateKey(nil)
	again := pantherclawv1connect.NewWorkloadServiceClient(s.connectClient(&workloadclient.Transport{Key: other}))
	otherJWK, _ := json.Marshal(jws.PublicJWK(otherPub, ""))
	_, err = again.Enroll(ctx, &pantherclawv1.EnrollRequest{PublicJwk: string(otherJWK), Attestation: att})
	if connect.CodeOf(err) != connect.CodeUnauthenticated || !strings.Contains(err.Error(), "invalid_token") {
		t.Errorf("reused attestation: %v", err)
	}
}
