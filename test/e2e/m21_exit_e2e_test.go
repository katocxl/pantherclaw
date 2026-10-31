// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	"github.com/katocxl/pantherclaw/internal/keystore"
	modelapp "github.com/katocxl/pantherclaw/internal/model/app"
	"github.com/katocxl/pantherclaw/internal/model/ports"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/outcomes"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	recapp "github.com/katocxl/pantherclaw/internal/recommendations/app"
	recdomain "github.com/katocxl/pantherclaw/internal/recommendations/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/search"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M21_BranchingRecommendationsMetricsDrafts is M21's exit journey
// (G0 M21 exit criteria). The server of the stack proves the new services are
// mounted behind authentication. The recommendations, outcome metrics and
// drafting legs run those services in the test on the stack's database, with
// a fake model provider. The automation leg runs the engine in the test on a
// database of its own, so the stack's workers do not advance its executions.
//
// Covers: F181, F304, F343, F678, F774
func TestE2E_M21_BranchingRecommendationsMetricsDrafts(t *testing.T) {
	s := start(t, options{budget: "1000.00"})
	t.Run("the new services are mounted behind authentication", s.m21Mounted)
	t.Run("a switch runs its path, v1 finishes unchanged, a cycle is refused", m21Automations)
	o := exposuretest.NewIn(t, s.db, s.pool)
	t.Run("a recommendation states its limits and stays in scope", func(t *testing.T) { m21Recommendation(t, o) })
	t.Run("a window without data is NOT_COLLECTED", func(t *testing.T) { m21Metrics(t, o) })
	t.Run("drafts stay drafts, and off means off", func(t *testing.T) { s.m21Drafts(t, o) })
}

// m21Mounted: each service answers its path and refuses an anonymous caller,
// where an unmounted one would answer 404.
func (s *stack) m21Mounted(t *testing.T) {
	for _, path := range []string{
		"/pantherclaw.v1.RecommendationService/ListRecommendations",
		"/pantherclaw.v1.OutcomeService/GetOutcomeMetrics",
		"/pantherclaw.v1.ModelService/GetModelSettings",
	} {
		r, err := http.NewRequest(http.MethodPost, s.apiURL+path, strings.NewReader("{}"))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", path, resp.StatusCode)
		}
	}
}

// m21Automation is a manual automation of body on the API version.
func m21Automation(version, body string) string {
	return `{"apiVersion":"` + version + `","kind":"Automation","purpose":"test","work_kind":"AGENT_WORK",
		"review_by":"` + time.Now().AddDate(0, 0, 30).Format(time.DateOnly) + `",
		"when":{"manual":{"params":{"ticket":{"type":"string","pattern":"T-[0-9]+"}}}},
		"authority":{"principal":"self","platform":[{"step":"revoke_grant","scopes":["EXECUTION"]}]},` + body + `}`
}

// The steps revoke, the one generic step a fake can finish with evidence
// (finish_when needs it, D2).
const (
	m21Revoke = `"step":"revoke_grant","with":{"scope":"EXECUTION"}`
	m21Switch = `"nodes":[
	{"id":"route","switch":{"cases":[{"when":"trigger.params.ticket == 'T-1'","next":"first"}],"default":"other"}},
	{"id":"first",` + m21Revoke + `,"next":"done"},
	{"id":"other",` + m21Revoke + `,"next":"ended"},
	{"id":"done","outcome":"SUCCEEDED","finish_when":[{"step":"first","condition":"GRANT_REVOKED"}]},
	{"id":"ended","outcome":"SUCCEEDED","finish_when":[{"step":"other","condition":"GRANT_REVOKED"}]}]`
	m21Line = `"do":[{"id":"pause",` + m21Revoke + `}],"finish_when":[{"step":"pause","condition":"GRANT_REVOKED"}]`
)

// m21Grants is the steps' grants: every revocation revokes one grant.
type m21Grants struct{}

func (m21Grants) IssueForAutomation(context.Context, pgx.Tx, steps.LaunchIssue) (ids.UUID, error) {
	return ids.UUID{}, errors.New("no launch in this journey")
}

func (m21Grants) RevokeForAutomation(context.Context, pgx.Tx, steps.GrantRevoke) ([]ids.UUID, error) {
	return []ids.UUID{ids.NewV7()}, nil
}

// m21Run starts an execution of the automation and works it to its end,
// returning its state, the node ids of its attempts and its stored path.
func m21Run(t *testing.T, f *triggerstest.Fixture, e *pgengine.Engine, a triggerstest.Automation, ticket string) (string, []string, []string) {
	t.Helper()
	trig := ids.NewV7()
	var exec ids.UUID
	f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO pc.automation_triggers (org_id, id, automation_id, version_id, kind, mode, source_ref,
			authenticity, params, root_trigger_id, state, occurred_at) VALUES ($1, $2, $3, $4, 'MANUAL', 'LIVE', 'manual:test',
			'USER_SESSION', '{}', $2, 'ACCEPTED', now())`, f.Org, trig, a.ID, a.Version); err != nil {
			return err
		}
		var err error
		exec, err = e.Start(ctx, tx.Pgx(), autodomain.TriggerRef{
			ID: trig, Org: f.Org, Automation: a.ID, Version: a.Version, Kind: autodomain.TriggerManual,
			Mode: autodomain.ModeLive, Root: trig, OccurredAt: time.Now(),
			Params: map[string]autodomain.Value{"ticket": {Type: autodomain.ParamString, String: ticket}},
		})
		return err
	})
	var state string
	var nodes, path []string
	read := func() {
		f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, `SELECT x.state, x.path, COALESCE((SELECT array_agg(s.node_id ORDER BY s.node_id)
				FROM pc.automation_step_attempts s WHERE s.org_id = x.org_id AND s.execution_id = x.id), '{}')
				FROM pc.automation_executions x WHERE x.org_id = $1 AND x.id = $2`, f.Org, exec).Scan(&state, &path, &nodes)
		})
	}
	for range 6 {
		f.Exec(t, `UPDATE pc.automation_step_attempts SET wake_at = now() - interval '1 second'
			WHERE org_id = $1 AND execution_id = $2 AND state IN ('RUNNING', 'WAITING')`, f.Org, exec)
		if err := e.Advance(context.Background(), f.Org, exec); err != nil {
			t.Fatal(err)
		}
		if read(); state != "RUNNING" && state != "WAITING" {
			break
		}
	}
	return state, nodes, path
}

// m21Enabled is an active automation with an approved ceiling, which a live
// execution needs.
func m21Enabled(t *testing.T, f *triggerstest.Fixture, name, def string) triggerstest.Automation {
	t.Helper()
	a := f.Automation(t, name, def, autodomain.RolloutFull)
	request := ids.NewV7()
	f.Exec(t, `INSERT INTO pc.change_requests (org_id, id, domain, kind, subject_id, content_digest, binding, summary, required,
		requested_by, expires_at) VALUES ($1, $2, 'automation', 'ENABLE', $3, $4, $4, '{}', 1, 'user:test', now() + interval '1 hour')`,
		f.Org, request, a.ID, bytes.Repeat([]byte{7}, 32))
	f.Exec(t, `INSERT INTO pc.automation_ceilings (org_id, id, automation_id, version_id, digest, approved_by, change_request_id,
		review_by) VALUES ($1, $2, $3, $4, $5, ARRAY[$6::uuid], $7, now() + interval '30 days')`,
		f.Org, ids.NewV7(), a.ID, a.Version, bytes.Repeat([]byte{8}, 32), f.User, request)
	return a
}

func m21Automations(t *testing.T) {
	f := triggerstest.New(t)
	e, err := pgengine.New(f.Pool, steps.Generic(steps.Deps{Grants: m21Grants{}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	v2 := m21Enabled(t, f, "routed", m21Automation(autodomain.APIVersionV2, m21Switch))
	for ticket, want := range map[string]string{"T-1": "first", "T-2": "other"} {
		state, nodes, _ := m21Run(t, f, e, v2, ticket)
		if state != "SUCCEEDED" || !slices.Equal(nodes, []string{want}) {
			t.Errorf("%s: %s through %v, want %s", ticket, state, nodes, want)
		}
	}

	v1 := m21Enabled(t, f, "line", m21Automation(autodomain.APIVersion, m21Line))
	if state, nodes, path := m21Run(t, f, e, v1, "T-1"); state != "SUCCEEDED" || !slices.Equal(nodes, []string{"pause"}) || len(path) != 0 {
		t.Errorf("v1: %s through %v, path %v", state, nodes, path)
	}

	d, err := autodomain.Parse([]byte(m21Automation(autodomain.APIVersionV2, strings.Replace(m21Switch, `"next":"done"`, `"next":"route"`, 1))))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(autodomain.Validate(context.Background(), d, m21Env{}), func(x autodomain.Finding) bool {
		return x.Code == autodomain.CodeCycle
	}) {
		t.Error("a cycle was not refused")
	}
}

// m21Env is a validation environment that allows everything.
type m21Env struct{}

func (m21Env) Now() time.Time                                            { return time.Now() }
func (m21Env) Owner() ids.UUID                                           { return ids.NewV7() }
func (m21Env) OwnerActivePerson(context.Context, ids.UUID) (bool, error) { return true, nil }
func (m21Env) AgentGrantable(context.Context, ids.UUID) (bool, error)    { return true, nil }
func (m21Env) Operation(context.Context, string) (autodomain.OperationInfo, error) {
	return autodomain.OperationInfo{Known: true}, nil
}

func (m21Env) EligibleApprovers(context.Context, autodomain.GateWith, ids.UUID, ids.UUID) (int, error) {
	return 1, nil
}

func (m21Env) DestinationActive(context.Context, ids.UUID, string) (bool, error) { return true, nil }
func (m21Env) Edition(autodomain.Edition) bool                                   { return true }

// m21Quiet takes the notices turning drafting on sends.
type m21Quiet struct{}

func (m21Quiet) Enqueue(context.Context, db.TenantTx, napp.Message) (napp.Enqueued, error) {
	return napp.Enqueued{}, nil
}

// m21Edition is a licensed edition.
type m21Edition billing.Edition

func (e m21Edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

// m21As is a person of the org holding role at scope.
func m21As(o *exposuretest.Org, role td.RoleName, scope td.Scope) context.Context {
	return tapp.WithCaller(context.Background(), tapp.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: role, Scope: scope}},
	}, Credential: tapp.CredBrowserSession})
}

func m21Org(o *exposuretest.Org) td.Scope { return td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()} }

func m21Recommendation(t *testing.T, o *exposuretest.Org) {
	a := o.Claim(t, o.Agent)
	b := o.Claim(t, o.Other)
	found := func(agent ids.UUID, kind string, key byte) {
		t.Helper()
		o.Exec(t, `INSERT INTO pc.discoveries (org_id, id, agent_id, source, scan_key, observed)
			VALUES ($1, $2, $3, 'scan', $4, jsonb_build_object('kind', 'env_secret', 'secret_kind', $5::text))`,
			o.Org, ids.NewV7(), agent, bytes.Repeat([]byte{key}, 32), kind)
	}
	found(o.Agent, "aws_secret_access_key", 9)
	found(o.Other, "openai_api_key", 10)
	svc := &recapp.Service{Pool: o.P, Ents: m21Edition(billing.Team)}
	find := func(ctx context.Context, id recdomain.ID) (recapp.Item, bool) {
		t.Helper()
		l, err := svc.List(ctx, false)
		if err != nil {
			t.Fatal(err)
		}
		i := slices.IndexFunc(l.Items, func(it recapp.Item) bool { return it.Entry.ID == id })
		if i < 0 {
			return recapp.Item{}, false
		}
		return l.Items[i], true
	}
	it, ok := find(m21As(o, td.RoleResponder, m21Org(o)), recdomain.AWSKeys)
	if !ok || len(it.Entry.Enables) == 0 || len(it.Entry.StillUnsupported) == 0 {
		t.Fatalf("the org's recommendation: %+v %v", it, ok)
	}
	team := func(id ids.UUID) context.Context {
		return m21As(o, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: id})
	}
	if _, ok := find(team(a), recdomain.AWSKeys); ok {
		t.Error("a team viewer sees an org-wide recommendation")
	}
	if _, ok := find(team(a), recdomain.ModelKeys); ok {
		t.Error("a team sees another team's discovery")
	}
	if _, ok := find(team(b), recdomain.ModelKeys); !ok {
		t.Error("a team does not see its own discovery")
	}
}

func m21Metrics(t *testing.T, o *exposuretest.Org) {
	o.D.AdminExec(t, "INSERT INTO pc.outcome_collection (org_id, started_at) VALUES ($1, now() - interval '60 days')", o.Org)
	ctx := context.Background()
	if n, err := (&outcomes.Rollup{Pool: o.P, Ents: m21Edition(billing.Business), Failures: &failures.Sink{}}).Run(ctx, o.Org); err != nil || n == 0 {
		t.Fatalf("rollup: %d, %v", n, err)
	}
	end := time.Now().UTC().Truncate(24 * time.Hour)
	r, err := (&outcomes.Service{Pool: o.P, Ents: m21Edition(billing.Business)}).GetMetrics(m21As(o, td.RoleAuditor, m21Org(o)), nil, 7, end.AddDate(0, 0, -1), end)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Series) < len(outcomes.Definitions) {
		t.Fatalf("%d series", len(r.Series))
	}
	for _, m := range r.Series {
		if m.Definition.Status != outcomes.DefinitionSignedOff {
			t.Errorf("%s: %s", m.Definition.Name, m.Definition.Status)
		}
		if p := m.Points[0]; p.State != outcomes.NotCollected || p.P50 != nil || p.Share != nil || len(p.Reasons) == 0 {
			t.Errorf("%s/%s: %+v", m.Definition.Name, m.Dimension, p)
		}
	}
}

// m21Provider is the fake model provider; the test reaches no real one.
type m21Provider struct {
	output string
	calls  int
}

func (p *m21Provider) Draft(context.Context, ports.DraftRequest) (ports.DraftResponse, error) {
	p.calls++
	return ports.DraftResponse{Output: []byte(p.output), InputTokens: 10, OutputTokens: 5}, nil
}

// m21Operations is the operations a draft may name.
type m21Operations []string

func (o m21Operations) VisibleOperations(context.Context) ([]string, error) { return o, nil }

func (o m21Operations) ActiveDefinitionsInTx(context.Context, db.TenantTx, ids.OrgID) ([]*defs.Definition, error) {
	out := make([]*defs.Definition, 0, len(o))
	for _, op := range o {
		out = append(out, &defs.Definition{Operation: op, Digest: op})
	}
	return out, nil
}

func (s *stack) m21Drafts(t *testing.T, o *exposuretest.Org) {
	kp, err := keys.NewFileProvider([]string{s.kek})
	if err != nil {
		t.Fatal(err)
	}
	cred := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.webauthn_credentials (org_id, id, user_id, credential_id, public_key, alg, backup_eligible,
		backup_state, attestation_fmt, name) VALUES ($1, $2, $3, $4, $5, -7, false, false, 'none', 'key')`,
		o.Org, cred, o.User, bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 32))
	const refund = "payments.refund.create"
	ops := m21Operations{refund}
	store := securitysteps.NewPolicyDrafts(&factspg.Store{Pool: o.P}, ops, celenv.DefaultLimits)
	fake := &m21Provider{output: `{"rules":[{"kind":"FORBID","summary":"Forbid refunds","operations":["payments.*"],"conditions":[],` +
		`"reason":"NO_REFUNDS","approval":null,"step_up":null,"constraint":null}],"ambiguities":[]}`}
	svc := &modelapp.Service{
		Pool: o.P, Envelope: pccrypto.NewEnvelope(keystore.NewCurrentCache(keystore.NewDEKStore(o.P, kp), time.Minute, clock.System{})),
		Editions: m21Edition(billing.Business), Notify: m21Quiet{}, Provider: fake, Policies: store, Operations: ops,
		Config: modelapp.Config{Enabled: true, CallsPerMinute: 100, TokensPerDay: 1_000_000},
	}
	admin := m21As(o, td.RoleOrgAdmin, m21Org(o))
	fresh := stepup.StepUp{Credential: cred, At: time.Now()}
	if _, err := svc.SetKey(admin, "sk-ant-e2e-test-key", fresh); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Enable(admin, fresh); err != nil {
		t.Fatal(err)
	}

	author := m21As(o, td.RolePolicyAuthor, m21Org(o))
	policy, err := svc.DraftPolicy(author, "forbid refunds")
	if err != nil {
		t.Fatal(err)
	}
	var state string
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, `SELECT v.state FROM pc.policy_versions v JOIN pc.model_drafts d
			ON d.org_id = v.org_id AND d.version_id = v.id AND d.kind = 'POLICY' AND d.origin = 'model'
			WHERE v.org_id = $1 AND v.id = $2`, o.Org, policy.Version).Scan(&state)
	})
	if state != "DRAFT" {
		t.Fatalf("a drafted policy is %q", state)
	}

	fake.output = `{"entity":"transactions","builtin":"","environment":"","outcomes":["denied"],"time":"last 7 days","names":[],"ambiguities":[]}`
	queries := &search.Drafter{Search: &search.Service{Pool: o.P, Defs: ops}, Model: svc, Builtin: ops}
	auditor := m21As(o, td.RoleAuditor, m21Org(o))
	drafted, err := queries.DraftQuery(auditor, "denied actions this week", "UTC")
	if err != nil {
		t.Fatal(err)
	}
	if in := drafted.Interpretation; in.Query == nil || in.NeedsClarification || drafted.Call.IsZero() {
		t.Fatalf("a drafted query: %+v", drafted)
	}
	// The draft is the answer: it carries a query to show, and no results.
	calls := fake.calls

	if _, err := svc.Disable(admin); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.DraftPolicy(author, "forbid refunds"); !errors.Is(err, modelapp.ErrOff) {
		t.Fatalf("a policy with drafting off: %v", err)
	}
	if _, err := queries.DraftQuery(auditor, "denied actions this week", "UTC"); !errors.Is(err, modelapp.ErrOff) {
		t.Fatalf("a query with drafting off: %v", err)
	}
	if fake.calls != calls {
		t.Fatalf("%d calls reached the provider with drafting off", fake.calls-calls)
	}
}
