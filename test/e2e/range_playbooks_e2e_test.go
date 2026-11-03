// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/automations/engine/adapters/pgengine"
	"github.com/katocxl/pantherclaw/internal/automations/securitysteps"
	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/triggerstest"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	detengine "github.com/katocxl/pantherclaw/internal/detection/engine"
	"github.com/katocxl/pantherclaw/internal/detection/pack"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestRange_ScenariosPlaybooks runs each response playbook of the Hub (G0 M27
// D508) on the real trigger service and engine, on the platform feed of a
// fresh Business organization, with the security steps' platform ties
// replaced by recorders. Each signal playbook starts from the audit entry the
// producing code writes, through the detection engine's built-in or published
// custom rules and Reflex's own alert and incident entries (D539): no alert
// is written by hand. A refused delegation revokes the grant it exceeded; a
// refused issue names no grant and only opens a case; a confirmed incident
// naming no run and a customer's (inferred, D526 P6) incident naming one
// suspend nothing (D514). Leaked-key and poisoned-mcp-server only open a
// case. It is
// part of `task range`.
//
// Covers: F942, F943
func TestRange_ScenariosPlaybooks(t *testing.T) {
	items, err := seed.Load(os.DirFS("../../hub"))
	if err != nil {
		t.Fatal(err)
	}
	var books []seed.Item
	for _, it := range items {
		if it.Entry.Kind == hubdomain.KindAutomation && strings.HasPrefix(it.Entry.Name, "pc.playbook.") {
			books = append(books, it)
		}
	}
	if len(books) != 6 {
		t.Fatalf("%d playbooks, want 6", len(books))
	}
	for _, it := range books {
		body, err := it.Item.DecodeBody()
		if err != nil {
			t.Fatal(err)
		}
		b := body.(hubdomain.AutomationBody)
		t.Run(it.Entry.Name, func(t *testing.T) {
			switch it.Entry.Name {
			case "pc.playbook.leaked-key":
				pbCaseOnly(t, b, pbNetworkChanged())
			case "pc.playbook.poisoned-mcp-server":
				pbCaseOnly(t, b, pbDrift())
			case "pc.playbook.rogue-sub-agent":
				pbRogueSubAgent(t, b)
			case "pc.playbook.compromised-laptop":
				pbCompromisedLaptop(t, b)
			case "pc.playbook.data-flow-hold-escalation":
				pbDataFlowHold(t, b)
			case "pc.playbook.offboarded-owner":
				pbOffboardedOwner(t, b)
			default:
				t.Fatalf("no range run for %s", it.Entry.Name)
			}
		})
	}
}

// The audit entries the producing code writes: identity/app tokens.go
// networkChanged, connections/app drift.go, grants/app delegate.go and
// service.go, grants/app grantEvent.
var (
	pbAgent    = "0192f942-0000-7000-8000-0000000019a1"
	pbInstance = "0192f942-0000-7000-8000-0000000019e1"
	pbParent   = "0192f942-0000-7000-8000-0000000019b1"
	pbChild    = "0192f942-0000-7000-8000-0000000019b2"
	pbRun      = "0192f942-0000-7000-8000-0000000019c1"
	pbConn     = "0192f942-0000-7000-8000-0000000019d1"
	pbTxn      = "0192f942-0000-7000-8000-0000000019f1"
)

func pbNetworkChanged() audit.Event {
	return audit.Event{
		Name: "security.instance_network_changed", Actor: evdomain.Actor{Type: "system", ID: "identity"}, Outcome: audit.Success,
		Object:  &audit.Object{Type: "instance", ID: pbInstance},
		Details: map[string]string{"agent_id": pbAgent, "from_network": "10.0.0.0/24", "to_network": "192.0.2.0/24"},
	}
}

func pbDrift() audit.Event {
	return audit.Event{
		Name: "package.transitioned", Actor: evdomain.Actor{Type: "gateway", ID: pbInstance}, Outcome: audit.Success,
		Object: &audit.Object{Type: "package_version", ID: "acme/refunds@1.0.0"},
		Details: map[string]string{
			"from": "ACTIVE", "to": "QUARANTINED", "reason": "upstream_drift", "connection_id": pbConn, "upstream_tool": "get_refund",
			"expected_digest": "sha256:aa", "observed_digest": "sha256:bb", "description_scan": "clean",
		},
	}
}

func pbDelegateRefused() audit.Event {
	return audit.Event{
		Name: "grant.delegate_refused", Actor: evdomain.Actor{Type: "instance", ID: pbInstance}, Outcome: audit.Denied,
		ReasonCode: "DELEGATION_EXCEEDS_PARENT", Object: &audit.Object{Type: "grant", ID: pbParent},
		Details: map[string]string{"agent": pbAgent, "parent": pbParent, "attempted": "grant.delegate"},
	}
}

func pbIssueRefused() audit.Event {
	return audit.Event{
		Name: "grant.issue_refused", Actor: evdomain.Actor{Type: "service_account", ID: pbInstance}, Outcome: audit.Denied,
		ReasonCode: "HUMAN_ONLY", Details: map[string]string{"attempted": "grant.issue", "agent": pbAgent},
	}
}

func pbDelegated() audit.Event {
	return audit.Event{
		Name: "grant.delegated", Actor: evdomain.Actor{Type: "instance", ID: pbInstance}, Outcome: audit.Success,
		Object:  &audit.Object{Type: "grant", ID: pbChild},
		Details: map[string]string{"parent": pbParent, "parent_revision": "1", "child_run": pbRun},
	}
}

// pbCaseOnly: the alert names a key or a connection, which a person revokes
// or disables; the playbook only opens a case.
func pbCaseOnly(t *testing.T, b hubdomain.AutomationBody, ev audit.Event) {
	r := newPBRange(t, b)
	x := r.produce(t, ev)
	r.drive(t, x)
	if st := r.step(t, x, "case"); st != "DONE" || r.cases.count() != 1 {
		t.Fatalf("case: %s, %d opened", st, r.cases.count())
	}
	if len(r.container.scopes()) != 0 || len(r.grants.revoked()) != 0 {
		t.Fatal("a case-only playbook contained something")
	}
}

// pbRogueSubAgent: pc.authority.self_issue fires on both refusals; only the
// refused delegation names a grant, and that grant is revoked.
func pbRogueSubAgent(t *testing.T, b hubdomain.AutomationBody) {
	for _, c := range []struct {
		name string
		ev   audit.Event
		want []string
	}{
		{"delegate_refused", pbDelegateRefused(), []string{pbParent}},
		{"issue_refused", pbIssueRefused(), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPBRange(t, b)
			x := r.produce(t, c.ev)
			r.drive(t, x)
			if got := r.grants.revoked(); !slices.Equal(got, c.want) {
				t.Fatalf("revoked %v, want %v", got, c.want)
			}
			want := "DONE"
			if c.want == nil {
				want = "SKIPPED"
			}
			if st := r.step(t, x, "contain"); st != want {
				t.Fatalf("contain: %s, want %s", st, want)
			}
			if st := r.step(t, x, "case"); st != "DONE" || r.cases.count() != 1 {
				t.Fatalf("case: %s, %d opened", st, r.cases.count())
			}
		})
	}
}

// pbCompromisedLaptop: a confirmed built-in incident (an action tampered in
// flight, which pages) names a transaction, not a run, so it suspends
// nothing. No built-in rule opens an incident naming a run; a customer's
// published rule can, on a delegation naming the child run, but its basis is
// INFERRED at most (D526 P6), so it suspends nothing either. Both open the
// case.
func pbCompromisedLaptop(t *testing.T, b hubdomain.AutomationBody) {
	for _, c := range []struct {
		name string
		rule string
		ev   audit.Event
	}{
		{"a confirmed incident on a transaction", "", audit.Event{
			Name: "security.action_tampered", Actor: evdomain.Actor{Type: "gateway", ID: pbInstance}, Outcome: audit.Denied,
			ReasonCode: "ACTION_TAMPERED", Object: &audit.Object{Type: "transaction", ID: pbTxn},
		}},
		{"a customer's incident on a run", pbIncidentRule, pbDelegated()},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := newPBRange(t, b)
			if c.rule != "" {
				r.publish(t, c.rule)
			}
			x := r.produce(t, c.ev)
			r.drive(t, x)
			if contained := r.container.scopes(); len(contained) != 0 {
				t.Fatalf("contained %v", contained)
			}
			if st := r.step(t, x, "contain"); st != "SKIPPED" {
				t.Fatalf("contain: %s, want SKIPPED", st)
			}
			if st := r.step(t, x, "case"); st != "DONE" || r.cases.count() != 1 {
				t.Fatalf("case: %s, %d opened", st, r.cases.count())
			}
		})
	}
}

const pbIncidentRule = `id: org.range.delegated_incident
version: "1"
title: Delegation under watch
description: A customer's rule that opens an incident on every delegation, naming the child run.
severity: HIGH
attention: INCIDENT
basis: INFERRED
edition: business
on: [audit.grant.delegated]
group: run
tests:
  - name: a delegation
    fires: true
    events:
      - kind: audit.grant.delegated
        actor_type: instance
        actor_id: 01930000-0000-7000-8000-0000000000i1
        outcome: success
        subjects: {grant: 01930000-0000-7000-8000-0000000000b2, run: 01930000-0000-7000-8000-0000000000c1}
  - name: a refused delegation
    fires: false
    events:
      - kind: audit.grant.delegate_refused
        actor_type: instance
        actor_id: 01930000-0000-7000-8000-0000000000i1
        outcome: denied
        subjects: {grant: 01930000-0000-7000-8000-0000000000b1}
`

// pbDataFlowHold: a decision held for its data flow starts the playbook; it
// opens a case and follows the approval request until a person decides it.
// It decides nothing itself. No range scenario produces a data-flow hold;
// the m16 exit journey does (TestE2E_M16_DataFlowHold), so this entry has the
// shape the pipeline writes.
func pbDataFlowHold(t *testing.T, b hubdomain.AutomationBody) {
	r := newPBRange(t, b)
	x := r.record(t, "receipt.decision", map[string]any{
		"txn": ids.NewV7().String(), "decision": "REQUIRE_APPROVAL", "reason": "DATA_FLOW_HOLD", "evaluation": ids.NewV7().String(),
	})
	r.drive(t, x)
	for _, s := range []string{"case", "pause", "remind", "escalate", "resolved"} {
		if st := r.step(t, x, s); st != "DONE" {
			t.Fatalf("step %s: %s", s, st)
		}
	}
	if n := r.approvals.nudged(); n != 2 {
		t.Fatalf("%d nudges, want a reminder and an escalation", n)
	}
	if len(r.container.scopes()) != 0 {
		t.Fatal("the hold playbook contained something")
	}
}

// pbOffboardedOwner: a person starts the playbook by hand; it asks the
// automation's owner to name a new owner and drafts no restriction when no
// grant went unused. Nothing is revoked or published.
func pbOffboardedOwner(t *testing.T, b hubdomain.AutomationBody) {
	r := newPBRange(t, b)
	ctx := r.f.As(td.KindUser, td.RoleAutomationOperator, td.RoleOrgAdmin)
	out, err := r.svc.StartExecution(ctx, triggers.ManualStart{
		Automation: r.a.ID, Params: map[string]string{"agent": ids.NewV7().String()}, IdempotencyKey: "offboard-1",
	}, nil)
	if err != nil || out.State != triggers.StateAccepted {
		t.Fatalf("StartExecution: %+v %v", out, err)
	}
	r.drive(t, out.Execution)
	for _, s := range []string{"assign", "draft", "simulate", "case"} {
		if st := r.step(t, out.Execution, s); st != "DONE" {
			t.Fatalf("step %s: %s", s, st)
		}
	}
	if r.failures.count() != 1 || r.cases.count() != 1 {
		t.Fatalf("owned failures %d, cases %d; want 1 and 1", r.failures.count(), r.cases.count())
	}
	if len(r.container.scopes()) != 0 || len(r.grants.revoked()) != 0 {
		t.Fatal("the offboarding playbook contained something")
	}
}

// pbRange is one Business organization with one playbook enabled FULL.
type pbRange struct {
	f         *triggerstest.Fixture
	a         triggerstest.Automation
	svc       *triggers.Service
	engine    *pgengine.Engine
	container *pbContainer
	grants    *pbGrants
	cases     *pbCounter
	failures  *pbCounter
	approvals *pbApprovals
}

func newPBRange(t *testing.T, b hubdomain.AutomationBody) *pbRange {
	t.Helper()
	f := triggerstest.New(t)
	r := &pbRange{
		f: f, container: &pbContainer{}, grants: &pbGrants{}, cases: &pbCounter{}, failures: &pbCounter{},
		approvals: &pbApprovals{request: ids.NewV7()},
	}
	business := triggerstest.Editions{Edition: billing.Business}
	reg := steps.Generic(steps.Deps{})
	for k, s := range securitysteps.All(securitysteps.Deps{
		Container: r.container, Actions: securitysteps.Actions{}, Cases: pbCases{r.cases}, Failures: pbFailures{r.failures},
		Owners: securitysteps.StoreOwners{}, Approvals: r.approvals, Grants: r.grants,
		Review: securitysteps.ReviewDeps{Unused: pbUnused{}, Drafts: pbDrafts{}},
	}) {
		reg[k] = s
	}
	e, err := pgengine.New(f.Pool, reg, pclog.Discard())
	if err != nil {
		t.Fatal(err)
	}
	e.Editions = business
	r.engine = e
	r.svc = triggers.New(triggers.Deps{Pool: f.Pool, Starter: e, Editions: business, Executions: e, Log: pclog.Discard()})
	// The draft a Hub install makes, with what a person sets before
	// validating it: the review date and, for a playbook that revokes, whose
	// grants it may revoke.
	def := b.Definition + "review_by: \"" + time.Now().AddDate(0, 0, 30).Format(time.DateOnly) + "\"\n"
	if strings.Contains(def, "REVOKE_GRANT") {
		def = strings.Replace(def, "authority:\n  principal: self\n", "authority:\n  principal: self\n  revocable:\n    all: true\n", 1)
		if !strings.Contains(def, "revocable:") {
			t.Fatal("no authority block to set revocable on")
		}
	}
	r.a = m21Enabled(t, f, b.AutomationName, def)
	r.feed(t) // the cursor starts at the head: history never triggers
	return r
}

func (r *pbRange) feed(t *testing.T) triggers.FeedResult {
	t.Helper()
	if _, err := ledger.ChainAll(context.Background(), r.f.Pool, r.f.Org, 1000); err != nil {
		t.Fatal(err)
	}
	res, err := r.svc.ProcessFeed(context.Background(), r.f.Org)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// pbEnts is the organization's edition for detections and Reflex.
var pbEnts = ents{billing.Business}

// publish creates and publishes a custom detection rule as a security admin
// (Business), with its tests.
func (r *pbRange) publish(t *testing.T, content string) {
	t.Helper()
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	det := &reflexapp.Detections{Pool: r.f.Pool, Env: env, Ents: pbEnts}
	ctx := r.f.As(td.KindUser, td.RoleSecurityAdmin)
	c, err := det.CreateCustomRule(ctx, content)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := det.PublishCustomRule(ctx, c.Custom.ID); err != nil {
		t.Fatal(err)
	}
}

// produce records ev as its producing code does, runs the detection engine
// over the feed with Reflex's own raiser, feeds the triggers and returns the
// execution they started.
func (r *pbRange) produce(t *testing.T, ev audit.Event) ids.UUID {
	t.Helper()
	eng := r.detector(t)
	r.detect(t, eng) // a new detection cursor starts at the head (D59 M4)
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
	if r.detect(t, eng) == 0 {
		t.Fatalf("%s raised no signal", ev.Name)
	}
	r.feed(t)
	return r.execution(t)
}

// detector is the detection engine with the built-in pack, the org's
// published custom rules and Reflex's own raiser, on Business.
func (r *pbRange) detector(t *testing.T) *detengine.Engine {
	t.Helper()
	env, err := detengine.NewEnv(celenv.DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	p, err := pack.Load(env)
	if err != nil {
		t.Fatal(err)
	}
	return &detengine.Engine{
		Pool: r.f.Pool, Builtin: p.Rules, PackVersion: p.Version, Env: env,
		Raiser: (&reflexapp.Hooks{Ents: pbEnts}).Raiser(), Sink: &failures.Sink{}, Ents: pbEnts,
	}
}

// detect chains the ledger and runs the engine over the feed until it is
// read, returning the signals raised.
func (r *pbRange) detect(t *testing.T, eng *detengine.Engine) int {
	t.Helper()
	ctx := context.Background()
	if _, err := ledger.ChainAll(ctx, r.f.Pool, r.f.Org, 1000); err != nil {
		t.Fatal(err)
	}
	signals := 0
	for range 50 {
		res, err := eng.Process(ctx, r.f.Org)
		if err != nil {
			t.Fatal(err)
		}
		signals += res.Signals
		if res.Events == 0 && res.To == res.From {
			break
		}
	}
	return signals
}

// record appends one ledger entry, feeds it to the triggers and returns the
// execution it started.
func (r *pbRange) record(t *testing.T, kind string, fields map[string]any) ids.UUID {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	body := jsontext.Value(raw)
	if err := body.Canonicalize(); err != nil {
		t.Fatal(err)
	}
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := ledger.Append(ctx, tx, kind, evdomain.Actor{Type: "system", ID: "reflex"}, body)
		return err
	})
	r.feed(t)
	return r.execution(t)
}

// execution is the one execution the playbook started.
func (r *pbRange) execution(t *testing.T) ids.UUID {
	t.Helper()
	var x ids.UUID
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.automation_executions WHERE org_id = $1 AND automation_id = $2", r.f.Org, r.a.ID).Scan(&x)
	})
	return x
}

// pbGrants records the grants contain REVOKE_GRANT revokes.
type pbGrants struct {
	mu    sync.Mutex
	calls []string
}

func (*pbGrants) IssueForAutomation(context.Context, pgx.Tx, steps.LaunchIssue) (ids.UUID, error) {
	return ids.UUID{}, errors.New("no launch in the playbooks")
}

func (g *pbGrants) RevokeForAutomation(_ context.Context, _ pgx.Tx, in steps.GrantRevoke) ([]ids.UUID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if in.Grant == nil {
		return nil, errors.New("no grant named")
	}
	g.calls = append(g.calls, in.Grant.String())
	return []ids.UUID{*in.Grant}, nil
}

func (g *pbGrants) revoked() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.calls)
}

// drive advances the execution, waking its waits, until it ends.
func (r *pbRange) drive(t *testing.T, x ids.UUID) {
	t.Helper()
	for range 20 {
		r.f.Exec(t, "UPDATE pc.automation_executions SET wake_at = now() - interval '1 second' WHERE id = $1 AND wake_at IS NOT NULL", x)
		r.f.Exec(t, "UPDATE pc.automation_step_attempts SET wake_at = now() - interval '1 second' WHERE execution_id = $1 AND wake_at IS NOT NULL", x)
		// A fixed wait ends at the `until` it recorded: move it to the past.
		r.f.Exec(t, `UPDATE pc.automation_step_attempts SET output = jsonb_set(output, '{until}', to_jsonb('2000-01-01T00:00:00Z'::text))
			WHERE execution_id = $1 AND state = 'WAITING' AND kind = 'wait' AND output ? 'until'`, x)
		if err := r.engine.Advance(context.Background(), r.f.Org, x); err != nil {
			t.Fatalf("advance: %v", err)
		}
		var state string
		r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
			return tx.QueryRow(ctx, "SELECT state FROM pc.automation_executions WHERE org_id = $1 AND id = $2", r.f.Org, x).Scan(&state)
		})
		if !slices.Contains([]string{"PENDING", "RUNNING", "WAITING"}, state) {
			return
		}
	}
	var states []string
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := tx.Query(ctx, `SELECT step_id || ':' || state || ':' || coalesce(reason, '') || ':' || coalesce(wake_at::text, '-')
			FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 ORDER BY started_at, step_index, attempt`, r.f.Org, x)
		if err != nil {
			return err
		}
		states, err = pgx.CollectRows(rows, pgx.RowTo[string])
		return err
	})
	t.Fatalf("the execution did not end: %v", states)
}

// step is the last attempt's state of a step, or "none".
func (r *pbRange) step(t *testing.T, x ids.UUID, id string) string {
	t.Helper()
	state := "none"
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		err := tx.QueryRow(ctx, `SELECT state FROM pc.automation_step_attempts WHERE org_id = $1 AND execution_id = $2 AND step_id = $3
			AND NOT compensation ORDER BY attempt DESC LIMIT 1`, r.f.Org, x, id).Scan(&state)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		return err
	})
	return state
}

// The recorders standing in for response, cases, owned failures, approvals
// and the policy store.

type pbContainer struct {
	mu    sync.Mutex
	calls []reflexdomain.ContainRequest
}

func (c *pbContainer) Contain(_ context.Context, _ pgx.Tx, req reflexdomain.ContainRequest) (reflexdomain.ContainResult, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, req)
	return reflexdomain.ContainResult{ActionID: ids.NewV7(), Status: "CONFIRMED"}, nil
}

func (c *pbContainer) scopes() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []string
	for _, r := range c.calls {
		out = append(out, string(r.Scope.Type)+":"+r.Scope.ID)
	}
	return out
}

type pbCounter struct {
	mu sync.Mutex
	n  int
}

func (c *pbCounter) add() ids.UUID {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return ids.NewV7()
}

func (c *pbCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

type pbCases struct{ c *pbCounter }

func (p pbCases) Open(context.Context, pgx.Tx, reflexdomain.CaseSeed) (ids.UUID, error) {
	return p.c.add(), nil
}

type pbFailures struct{ c *pbCounter }

func (p pbFailures) Report(context.Context, pgx.Tx, reflexdomain.Failure) (ids.UUID, error) {
	return p.c.add(), nil
}

type pbApprovals struct {
	request ids.UUID
	mu      sync.Mutex
	nudges  int
}

func (a *pbApprovals) RequestOf(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (ids.UUID, bool, error) {
	return a.request, true, nil
}

func (a *pbApprovals) Nudge(context.Context, pgx.Tx, ids.OrgID, ids.UUID, bool, string) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.nudges++
	return 1, nil
}

func (a *pbApprovals) Resolution(context.Context, pgx.Tx, ids.OrgID, ids.UUID) (securitysteps.Resolution, error) {
	return securitysteps.Resolution{State: "APPROVED", Resolved: true}, nil
}

func (a *pbApprovals) nudged() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.nudges
}

type pbUnused struct{}

func (pbUnused) Unused(context.Context, pgx.Tx, ids.OrgID, time.Time, int) ([]securitysteps.UnusedGrant, error) {
	return nil, nil
}

type pbDrafts struct{}

var errPBNoDraft = errors.New("the range drafts no policy")

func (pbDrafts) Published(context.Context, pgx.Tx, ids.OrgID) (*pdomain.Bundle, ids.UUID, error) {
	return nil, ids.UUID{}, errPBNoDraft
}

func (pbDrafts) CreateDraft(context.Context, pgx.Tx, ids.OrgID, *pdomain.Bundle, evdomain.Actor) (ids.UUID, int, error) {
	return ids.UUID{}, 0, errPBNoDraft
}
