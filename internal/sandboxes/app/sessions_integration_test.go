// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	adomain "github.com/katocxl/pantherclaw/internal/agents/domain"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	coverage "github.com/katocxl/pantherclaw/internal/coverage/app"
	covdomain "github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/db/dbtest"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/sandbox/report"
	"github.com/katocxl/pantherclaw/internal/sandboxes/app"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const (
	digest      = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	otherDigest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
)

type unlimited struct{}

func (unlimited) Current(context.Context) (billing.Entitlements, error) {
	e := billing.CommunityEntitlements()
	e.Edition, e.Limits.MaxAgents = billing.Business, billing.Unlimited
	return e, nil
}

type world struct {
	d                  *dbtest.DB
	pool, admin        *db.Pool
	svc                *app.Service
	org                ids.OrgID
	team, env, owner   ids.UUID
	agent, gateway, gh ids.UUID
	version            ids.UUID
	probeKey, hostKey  ed25519.PrivateKey
}

func newWorld(t *testing.T) *world {
	t.Helper()
	d := dbtest.New(t)
	p := d.AppPool(t)
	w := &world{
		d: d, pool: p, admin: d.Pool(t, d.Migrator), org: ids.New[ids.Org](), team: ids.NewV7(), env: ids.NewV7(), owner: ids.NewV7(),
		gateway: ids.NewV7(), gh: ids.NewV7(), version: ids.NewV7(),
		svc: &app.Service{Pool: p, Coverage: &coverage.Service{Pool: p, Freshness: covdomain.Freshness{EnforcedTTL: 24 * time.Hour, ReassessEvery: time.Minute}}},
	}
	_, w.probeKey, _ = ed25519.GenerateKey(rand.Reader)
	_, w.hostKey, _ = ed25519.GenerateKey(rand.Reader)
	w.exec(t, "INSERT INTO pc.orgs (id, name) VALUES ($1, 'acme')", w.org)
	w.exec(t, "INSERT INTO pc.teams (org_id, id, slug, name) VALUES ($1, $2, 'eng', 'Eng')", w.org, w.team)
	w.exec(t, "INSERT INTO pc.environments (org_id, id, team_id, slug, name, kind) VALUES ($1, $2, $3, 'dev', 'Dev', 'DEVELOPMENT')", w.org, w.env, w.team)
	w.exec(t, "INSERT INTO pc.users (org_id, id, issuer, subject) VALUES ($1, $2, 'https://idp.test', 'alice')", w.org, w.owner)
	w.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge', 'test')", w.org, w.gateway)
	// The connections' package, pinned: a mapped connection needs one.
	pkg := ids.NewV7()
	w.exec(t, "INSERT INTO pc.tool_packages (org_id, id, name) VALUES ($1, $2, 'pc.github')", w.org, pkg)
	w.exec(t, `INSERT INTO pc.package_versions (org_id, id, package_id, version, file_digest, raw, state)
		VALUES ($1, $2, $3, '1.0.0', $4, '\x7b7d', 'ACTIVE')`, w.org, w.version, pkg, digest)
	w.exec(t, `INSERT INTO pc.package_pins (org_id, package_id, version_id, version, digest) VALUES ($1, $2, $3, '1.0.0', $4)`,
		w.org, pkg, w.version, digest)
	w.connection(t, w.gh, "github", w.gateway, []string{"api.github.com"})
	a, err := aapp.NewInventory(p, unlimited{}).Create(w.as(td.RoleAgentOwner), adomain.Details{
		Name: "coder", TeamID: w.team, EnvironmentID: w.env, OwnerUserID: w.owner, Context: adomain.ContextCI,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.agent = a.ID
	return w
}

func (w *world) connection(t *testing.T, id ids.UUID, name string, gateway ids.UUID, hosts []string) {
	t.Helper()
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by, agent_hosts) VALUES ($1, $2, $3, 'http', $4, 'pc.github', 'https://api.github.com',
		'pantherclaw_held', 'enforce', 'test', 'test', $5)`, w.org, id, name, gateway, hosts)
}

func (w *world) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

// asAdmin runs sql with the migrator, which may change what pc_app may not.
func (w *world) asAdmin(t *testing.T, sql string, args ...any) {
	t.Helper()
	if err := w.admin.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, sql, args...)
		return err
	}); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func (w *world) count(t *testing.T, sql string, args ...any) int {
	t.Helper()
	var n int
	if err := w.pool.InTenantTx(context.Background(), w.org, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, sql, args...).Scan(&n)
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

// as is the owner holding roles at the team.
func (w *world) as(roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeTeam, ID: w.team}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: w.owner}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

func (w *world) input() app.StartInput {
	return app.StartInput{
		Agent: w.agent, Connections: []ids.UUID{w.gh}, AgentImage: digest, EdgeImage: digest, ProbeImage: digest, ConfigDigest: digest,
		ProbeKey: w.probeKey.Public().(ed25519.PublicKey), HostKey: w.hostKey.Public().(ed25519.PublicKey), EngineVersion: "29.8.2",
		EngineAPI: "1.56", Runtime: "runc",
	}
}

// admit stands in for pclaw's enrollment and admission of the session's
// sandbox instance (identity's own tests cover those).
func (w *world) admit(t *testing.T, s app.Started) ids.UUID {
	t.Helper()
	id := ids.NewV7()
	jkt := make([]byte, 32)
	_, _ = rand.Read(jkt)
	w.exec(t, `INSERT INTO pc.agent_instances (org_id, id, agent_id, jkt, public_jwk, state, enrolled_via, enrollment_token_id)
		VALUES ($1, $2, $3, $4, '{}', 'ADMITTED', 'enrollment_token', $5)`,
		w.org, id, w.agent, base64.RawURLEncoding.EncodeToString(jkt), s.Session.EnrollmentTokenID)
	return id
}

// signed is a report of kind for the session, with the session's facts
// (its images and configuration), signed with the key of its kind: the
// probe key for the sandbox run, the host key for the control run and the
// canary.
func (w *world) signed(t *testing.T, s app.Started, kind, nonce string, mutate func(*report.Report)) string {
	t.Helper()
	key := w.hostKey
	if kind == report.KindSandbox {
		key = w.probeKey
	}
	return w.signedWith(t, key, s, kind, nonce, mutate)
}

func (w *world) signedWith(t *testing.T, key ed25519.PrivateKey, s app.Started, kind, nonce string, mutate func(*report.Report)) string {
	t.Helper()
	at := time.Now().UTC().Add(-time.Minute)
	r := report.Report{
		Format: report.Format, Session: s.Session.ID.String(), Nonce: nonce, Kind: kind, StartedAt: at, FinishedAt: at.Add(30 * time.Second),
		Images:  report.Images{Agent: s.Session.AgentImage, Edge: s.Session.EdgeImage, Probe: s.Session.ProbeImage},
		Engine:  report.Engine{Version: "29.8.2", APIVersion: "1.56", Runtime: "runc", Desktop: true},
		Network: report.Network{Name: "pc-sbx-1", Internal: true, GatewayModeIPv4: "isolated"},
		Config:  report.Config{Digest: s.Session.ConfigDigest, Checks: []report.Check{{ID: "read_only_root", OK: true}}},
		Results: []report.Result{{Name: "ipv6", Role: report.RoleProbe, Expect: report.Blocked, Observed: report.Blocked}},
		Canary:  report.Canary{Hits: []report.Hit{}},
	}
	if mutate != nil {
		mutate(&r)
	}
	compact, err := report.Sign(key, r)
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

func TestHR215_AReportIsAcceptedOnceWithItsSessionsKeyNonceAndFacts(t *testing.T) {
	w := newWorld(t)
	s, err := w.svc.StartSession(w.as(td.RoleAgentOwner), w.input())
	if err != nil {
		t.Fatal(err)
	}
	if s.AgentHosts["api.github.com"] != "github" || s.EnrollmentToken.String() == "" || s.Nonces.Sandbox == s.Nonces.Control {
		t.Fatalf("started %+v", s)
	}
	ctx := w.as(td.RoleAgentOwner)
	sandbox := w.signed(t, s, report.KindSandbox, s.Nonces.Sandbox, nil)
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, sandbox, nil); !errors.Is(err, app.ErrReport) {
		t.Fatalf("before the instance was admitted: %v", err)
	}
	inst := w.admit(t, s)
	a, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, sandbox, nil)
	if err != nil || a.Kind != app.KindSandbox || len(a.Failed) != 0 {
		t.Fatalf("sandbox report: %+v, %v", a, err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.agent_instances WHERE id = $1 AND sandbox_session_id = $2", inst, s.Session.ID); n != 1 {
		t.Fatal("the instance is not marked as the session's")
	}
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, sandbox, nil); !errors.Is(err, app.ErrReport) {
		t.Fatalf("a replayed report: %v", err)
	}
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, w.signed(t, s, report.KindControl, s.Nonces.Control, nil), nil); err != nil {
		t.Fatalf("control report: %v", err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.probe_runs WHERE session_id = $1", s.Session.ID); n != 2 {
		t.Fatalf("%d reports kept", n)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.sandbox.report_rejected'"); n != 2 {
		t.Fatalf("%d rejections recorded", n)
	}
}

// TestT087_ForgedReplayedAndStaleReportsAreRejected: every way to pass off
// a report the session's probe did not produce is refused and recorded.
func TestT087_ForgedReplayedAndStaleReportsAreRejected(t *testing.T) {
	w := newWorld(t)
	ctx := w.as(td.RoleAgentOwner)
	s, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	w.admit(t, s)
	other, err := w.svc.StartSession(ctx, w.input())
	if err != nil {
		t.Fatal(err)
	}
	_, stranger, _ := ed25519.GenerateKey(rand.Reader)
	n := s.Nonces.Sandbox
	for name, compact := range map[string]string{
		"another key": func() string {
			k := w.probeKey
			w.probeKey = stranger
			defer func() { w.probeKey = k }()
			return w.signed(t, s, report.KindSandbox, n, nil)
		}(),
		"another session's nonce":           w.signed(t, s, report.KindSandbox, other.Nonces.Sandbox, nil),
		"the control's nonce":               w.signed(t, s, report.KindSandbox, s.Nonces.Control, nil),
		"another session":                   w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Session = other.Session.ID.String() }),
		"another image":                     w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Images.Edge = otherDigest }),
		"another configuration":             w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Config.Digest = otherDigest }),
		"Docker 27":                         w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Engine.Version = "27.5.1" }),
		"another runtime":                   w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Engine.Runtime = "runsc" }),
		"an open network":                   w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Network.GatewayModeIPv4 = "nat" }),
		"a failed check":                    w.signed(t, s, report.KindSandbox, n, func(r *report.Report) { r.Config.Checks[0].OK = false }),
		"a canary report":                   w.signed(t, s, report.KindCanary, s.Nonces.Canary, nil),
		"unsigned":                          w.signed(t, s, report.KindSandbox, n, nil)[:40] + "x.y",
		"a sandbox report on the host key":  w.signedWith(t, w.hostKey, s, report.KindSandbox, n, nil),
		"a control report on the probe key": w.signedWith(t, w.probeKey, s, report.KindControl, s.Nonces.Control, nil),
	} {
		if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, compact, nil); !errors.Is(err, app.ErrReport) {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A stale nonce: issued 20 minutes ago.
	w.asAdmin(t, `UPDATE pc.probe_nonces SET created_at = now() - interval '20 minutes', expires_at = now() - interval '5 minutes'
		WHERE session_id = $1`, s.Session.ID)
	if _, err := w.svc.SubmitProbeReport(ctx, s.Session.ID, w.signed(t, s, report.KindSandbox, n, nil), nil); !errors.Is(err, app.ErrReport) {
		t.Errorf("stale nonce: %v", err)
	}
	if n := w.count(t, "SELECT count(*) FROM pc.probe_runs"); n != 0 {
		t.Fatalf("%d reports kept", n)
	}
	// An ended session takes nothing.
	w.asAdmin(t, "UPDATE pc.sandbox_sessions SET state = 'ENDED', ended_at = now() WHERE id = $1", other.Session.ID)
	if _, err := w.svc.SubmitProbeReport(ctx, other.Session.ID, w.signed(t, other, report.KindSandbox, other.Nonces.Sandbox, nil), nil); !errors.Is(err, app.ErrNotOpen) {
		t.Errorf("ended session: %v", err)
	}
}

func TestStartSessionChecksTheCallerAndTheConnections(t *testing.T) {
	w := newWorld(t)
	if _, err := w.svc.StartSession(w.as(td.RoleViewer), w.input()); err == nil {
		t.Fatal("a viewer opened a session")
	}
	if _, err := w.svc.StartSession(w.as(td.RoleDeveloper), w.input()); err != nil {
		t.Fatalf("a developer: %v", err)
	}
	noHosts, otherGateway, gw2 := ids.NewV7(), ids.NewV7(), ids.NewV7()
	w.connection(t, noHosts, "payments", w.gateway, []string{})
	w.exec(t, "INSERT INTO pc.gateways (org_id, id, name, created_by) VALUES ($1, $2, 'edge2', 'test')", w.org, gw2)
	w.connection(t, otherGateway, "github2", gw2, []string{"uploads.github.com"})
	same := ids.NewV7()
	w.connection(t, same, "github3", w.gateway, []string{"api.github.com"})
	unpinned := ids.NewV7()
	w.exec(t, `INSERT INTO pc.connections (org_id, id, name, kind, gateway_id, package, base_url, access_mode, default_mode,
		created_by, updated_by, agent_hosts) VALUES ($1, $2, 'other', 'http', $3, 'pc.unpinned', 'https://api.other.test',
		'none', 'enforce', 'test', 'test', ARRAY['api.other.test'])`, w.org, unpinned, w.gateway)
	for name, conns := range map[string][]ids.UUID{
		"no agent hosts":    {noHosts},
		"two gateways":      {w.gh, otherGateway},
		"a host twice":      {w.gh, same},
		"an unknown one":    {ids.NewV7()},
		"no pinned package": {unpinned},
	} {
		in := w.input()
		in.Connections = conns
		if _, err := w.svc.StartSession(w.as(td.RoleAgentOwner), in); !errors.Is(err, app.ErrConnections) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, mutate := range map[string]func(*app.StartInput){
		"one key for both": func(in *app.StartInput) { in.HostKey = in.ProbeKey },
		"no host key":      func(in *app.StartInput) { in.HostKey = nil },
	} {
		in := w.input()
		mutate(&in)
		if _, err := w.svc.StartSession(w.as(td.RoleAgentOwner), in); !errors.Is(err, app.ErrKeys) {
			t.Errorf("%s: %v", name, err)
		}
	}
	in := w.input()
	in.Agent = ids.NewV7()
	if _, err := w.svc.StartSession(w.as(td.RoleAgentOwner), in); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("an unknown agent: %v", err)
	}
}

// TestASessionHoldsItsProbeKeyHashedNoncesAndEnrollment: an opened session
// stores the probe key its reports must verify with, three nonces as their
// SHA-256 only, and an enrollment for its sandbox instance; it is audited,
// and only readers of the agent's coverage see it (HR-215).
func TestASessionHoldsItsProbeKeyHashedNoncesAndEnrollment(t *testing.T) {
	w := newWorld(t)
	s, err := w.svc.StartSession(w.as(td.RoleAgentOwner), w.input())
	if err != nil {
		t.Fatal(err)
	}
	if s.Session.State != "OPEN" || !bytes.Equal(s.Session.ProbePublicKey, w.probeKey.Public().(ed25519.PublicKey)) ||
		!bytes.Equal(s.Session.HostPublicKey, w.hostKey.Public().(ed25519.PublicKey)) ||
		s.EnrollmentToken.String() == "" || s.AgentHosts["api.github.com"] != "github" || len(s.Connections) != 1 {
		t.Fatalf("started %+v", s)
	}
	for _, n := range []string{s.Nonces.Sandbox, s.Nonces.Control, s.Nonces.Canary} {
		sum := sha256.Sum256([]byte(n))
		if c := w.count(t, "SELECT count(*) FROM pc.probe_nonces WHERE session_id = $1 AND nonce_sha256 = $2 AND used_at IS NULL", s.Session.ID, sum[:]); c != 1 {
			t.Errorf("nonce stored %d times", c)
		}
	}
	if c := w.count(t, "SELECT count(*) FROM pc.ledger_entries WHERE kind = 'audit.sandbox.session_started'"); c != 1 {
		t.Errorf("%d session_started audit entries", c)
	}
	// The connection's bindings as the session opened (the closure
	// contract's Bound).
	if c := w.count(t, `SELECT count(*) FROM pc.sandbox_session_connections WHERE session_id = $1 AND connection_id = $2
		AND connection_revision = 1 AND gateway_id = $3 AND package_version_id = $4 AND credential_version IS NULL`,
		s.Session.ID, w.gh, w.gateway, w.version); c != 1 {
		t.Errorf("the connection's bindings stored %d times", c)
	}
	got, conns, err := w.svc.GetSession(w.as(td.RoleAgentOwner), s.Session.ID)
	if err != nil || got.ID != s.Session.ID || len(conns) != 1 || conns[0] != w.gh {
		t.Fatalf("get: %+v %v %v", got, conns, err)
	}
	if list, err := w.svc.ListSessions(w.as(td.RoleAgentOwner), &w.agent, nil, 10); err != nil || len(list) != 1 {
		t.Fatalf("list: %d, %v", len(list), err)
	}
	if _, _, err := w.svc.GetSession(w.as(td.RoleViewer), s.Session.ID); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("a viewer read the session: %v", err)
	}
	if list, err := w.svc.ListSessions(w.as(td.RoleViewer), nil, nil, 10); err != nil || len(list) != 0 {
		t.Errorf("a viewer listed %d sessions, %v", len(list), err)
	}
}
