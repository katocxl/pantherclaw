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
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	hubdomain "github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/hub/seed"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestRange_ScenariosPlaybooks runs each response playbook of the Hub (G0 M27
// D508) on the real trigger service and engine, on the platform feed of a
// fresh organization, with the security steps' platform ties replaced by
// recorders. A playbook that can contain is run twice: on a CONFIRMED alert
// it suspends the triggering run and opens a case; on an inferred one it
// suspends nothing and still opens the case (D514). It is part of `task
// range`.
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
		switch it.Entry.Name {
		case "pc.playbook.leaked-key":
			pbSignal(t, b, "reflex.alert", "pc.identity.key_new_network")
		case "pc.playbook.poisoned-mcp-server":
			pbSignal(t, b, "reflex.alert", "pc.tools.drift")
		case "pc.playbook.rogue-sub-agent":
			pbSignal(t, b, "reflex.alert", "pc.authority.self_issue")
		case "pc.playbook.compromised-laptop":
			pbSignal(t, b, "reflex.incident", "")
		case "pc.playbook.data-flow-hold-escalation":
			t.Run(it.Entry.Name, func(t *testing.T) { pbDataFlowHold(t, b) })
		case "pc.playbook.offboarded-owner":
			t.Run(it.Entry.Name, func(t *testing.T) { pbOffboardedOwner(t, b) })
		default:
			t.Fatalf("no range run for %s", it.Entry.Name)
		}
	}
}

// pbSignal runs a containing playbook on a confirmed and on an inferred
// signal of kind (reflex.alert or reflex.incident).
func pbSignal(t *testing.T, b hubdomain.AutomationBody, kind, rule string) {
	t.Helper()
	for _, basis := range []string{"OBSERVED", "INFERRED"} {
		t.Run("pc.playbook."+strings.TrimPrefix(b.AutomationName, "hub-playbook-")+"/"+basis, func(t *testing.T) {
			r := newPBRange(t, b)
			run := ids.NewV7().String()
			fields := map[string]any{
				"id": ids.NewV7().String(), "state": "OPEN", "severity": "HIGH", "basis": basis,
				"subjects": []map[string]string{{"type": "run", "id": run}},
			}
			if kind == "reflex.alert" {
				fields["rule"], fields["attention"] = rule, "ALERT"
			} else {
				fields["attention"] = "INCIDENT"
			}
			x := r.record(t, kind, fields)
			r.drive(t, x)
			contained := r.container.scopes()
			switch basis {
			case "OBSERVED":
				if !slices.Equal(contained, []string{"run:" + run}) {
					t.Fatalf("a confirmed signal contained %v, want the triggering run %s", contained, run)
				}
				if st := r.step(t, x, "contain"); st != "DONE" {
					t.Fatalf("contain on a confirmed signal: %s", st)
				}
			default:
				if len(contained) != 0 {
					t.Fatalf("an inferred signal contained %v", contained)
				}
				if st := r.step(t, x, "contain"); st != "SKIPPED" {
					t.Fatalf("contain on an inferred signal: %s", st)
				}
			}
			if st := r.step(t, x, "case"); st != "DONE" || r.cases.count() != 1 {
				t.Fatalf("case: %s, %d opened", st, r.cases.count())
			}
		})
	}
}

// pbDataFlowHold: a decision held for its data flow starts the playbook; it
// opens a case and follows the approval request until a person decides it.
// It decides nothing itself.
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
	if len(r.container.scopes()) != 0 {
		t.Fatal("the offboarding playbook contained something")
	}
}

// pbRange is one organization with one playbook enabled FULL on Business.
type pbRange struct {
	f         *triggerstest.Fixture
	a         triggerstest.Automation
	svc       *triggers.Service
	engine    *pgengine.Engine
	container *pbContainer
	cases     *pbCounter
	failures  *pbCounter
	approvals *pbApprovals
}

func newPBRange(t *testing.T, b hubdomain.AutomationBody) *pbRange {
	t.Helper()
	f := triggerstest.New(t)
	r := &pbRange{f: f, container: &pbContainer{}, cases: &pbCounter{}, failures: &pbCounter{}, approvals: &pbApprovals{request: ids.NewV7()}}
	business := triggerstest.Editions{Edition: billing.Business}
	reg := steps.Generic(steps.Deps{})
	for k, s := range securitysteps.All(securitysteps.Deps{
		Container: r.container, Actions: securitysteps.Actions{}, Cases: pbCases{r.cases}, Failures: pbFailures{r.failures},
		Owners: securitysteps.StoreOwners{}, Approvals: r.approvals,
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
	// The draft a Hub install makes, with the review date a person sets
	// before validating it.
	def := b.Definition + "review_by: \"" + time.Now().AddDate(0, 0, 30).Format(time.DateOnly) + "\"\n"
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
	var x ids.UUID
	r.f.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		return tx.QueryRow(ctx, "SELECT id FROM pc.automation_executions WHERE org_id = $1 AND automation_id = $2", r.f.Org, r.a.ID).Scan(&x)
	})
	return x
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
