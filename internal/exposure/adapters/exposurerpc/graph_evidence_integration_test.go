// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exposurerpc_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/app"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func edgesOf(g *pb.GetGraphResponse, kind string) []*pb.GraphEdge {
	return slices.DeleteFunc(slices.Clone(g.GetEdges()), func(e *pb.GraphEdge) bool { return e.GetKind() != kind })
}

func gapNamed(g *pb.GetGraphResponse, missing string) bool {
	return slices.ContainsFunc(edgesOf(g, "gap"), func(e *pb.GraphEdge) bool { return e.GetProvenance() == missing })
}

// receipted gives txn a grant and its decision, execution and effect
// receipts.
func receipted(t *testing.T, w *world, txn, grant ids.UUID) {
	t.Helper()
	o := w.o
	entry := func() ids.UUID {
		id := ids.NewV7()
		o.Exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			VALUES ($1, $2, 'decision.test', 'test', 'test', '\x7b7d')`, o.Org, id)
		return id
	}
	o.D.AdminExec(t, `UPDATE pc.transactions SET grant_id = $2, grant_revision = 1, effect_state = 'CONFIRMED',
		effect_level_required = 'acceptance', effect_level_achieved = 'acceptance', downstream_state = 'PENDING' WHERE id = $1`, txn, grant)
	o.Exec(t, `INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id)
		VALUES ($1, $2, 1, 'x.y.z', $3)`, o.Org, txn, entry())
	o.Exec(t, `INSERT INTO pc.execution_receipts (org_id, attempt_id, transaction_id, permit_id, receipt_jws, ledger_entry_id)
		SELECT a.org_id, a.id, a.transaction_id, a.permit_id, 'xxxxxxxxxxxxxxxxxxxx', $2 FROM pc.execution_attempts a WHERE a.transaction_id = $1`,
		txn, entry())
	o.Exec(t, `INSERT INTO pc.effect_receipts (org_id, transaction_id, seq, state, level_required, level_achieved, basis, receipt_jws, ledger_entry_id)
		VALUES ($1, $2, 1, 'CONFIRMED', 'acceptance', 'acceptance', 'verifier', 'xxxxxxxxxxxxxxxxxxxx', $3)`, o.Org, txn, entry())
}

// consequence records position of txn's decision, and with a transaction
// when opened is set.
func consequence(t *testing.T, w *world, txn ids.UUID, position int, state string, opened bool) ids.UUID {
	t.Helper()
	o := w.o
	digest := "sha256:" + strings.Repeat("0", 64)
	o.Exec(t, `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type,
		target_id, state, facts_digest, "unknown") VALUES ($1, $2, 1, $3, 'rule', 'github.deployment.trigger', 'repo', 'r', $4, $5,
		CASE WHEN $4 = 'UNKNOWN' THEN '[{"fact":"x"}]'::jsonb ELSE '[]'::jsonb END)`, o.Org, txn, position, state, digest)
	if !opened {
		return ids.UUID{}
	}
	id := ids.NewV7()
	o.Exec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code, gateway_id,
		connection_id, mode, consequence_root, consequence_position, grant_id, grant_revision)
		SELECT $1, $2, $3, $4, $5, 'github.deployment.trigger', 'ALLOW', 'CONSEQUENCE', 'gw', $6, 'enforce', $7, $8, grant_id, grant_revision
		FROM pc.transactions WHERE id = $7`, o.Org, id, o.Run, ids.NewV7(), make([]byte, 32), o.Conn, txn, position)
	o.Exec(t, `INSERT INTO pc.transaction_links (org_id, from_transaction_id, to_transaction_id, kind, created_by)
		VALUES ($1, $2, $3, 'consequence', 'test')`, o.Org, txn, id)
	return id
}

// TestHR551_TheCausalGraphNamesTheRecordBehindEachLink: over stored
// records the causal graph links authority, custody, effect and downstream
// consequence, each to its record, keeps a prediction apart from what an
// opened transaction shows, and marks what is unproven as a gap.
// Covers: F272, F279, F280, F281
func TestHR551_TheCausalGraphNamesTheRecordBehindEachLink(t *testing.T) {
	w := newWorld(t, billing.Team)
	grant := w.o.Grant(t, w.o.Agent, 0, "", "github.*")
	txn := w.o.Dispatch(t, "github.pull_request.merge")
	receipted(t, w, txn, grant)
	consequence(t, w, txn, 0, "PREDICTED", false)
	opened := consequence(t, w, txn, 1, "PREDICTED", true)
	consequence(t, w, txn, 2, "UNKNOWN", false)

	scope := &pb.GraphScope{Type: "run", Id: w.o.Run.String()}
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_CAUSAL, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	has := func(kind, to, ref string) *pb.GraphEdge {
		for _, e := range edgesOf(g, kind) {
			if e.GetTo().GetId() == to && strings.HasPrefix(e.GetEvidenceRef(), ref) {
				return e
			}
		}
		t.Fatalf("no %s edge to %s with %s in %v", kind, to, ref, g.GetEdges())
		return nil
	}
	has("authorized", txn.String(), "decision_receipt:"+txn.String())
	has("custody", txn.String(), "execution_receipt:")
	e := has("effect", txn.String()+"/1", "effect_receipt:"+txn.String()+"/1")
	if e.GetEffect() != "CONFIRMED" || e.GetDownstreamState() != "PENDING" || e.GetProvenance() != "verifier" {
		t.Errorf("effect edge: %v", e)
	}
	p := has("triggered", txn.String()+"/0", "decision_consequence:")
	if p.GetTriggerStage() != pb.GraphTriggerStage_GRAPH_TRIGGER_STAGE_PREDICTED || p.GetState() != pb.GraphEdgeState_GRAPH_EDGE_STATE_POSSIBLE {
		t.Errorf("predicted: %v", p)
	}
	a := has("triggered", opened.String(), "transaction_link:")
	if a.GetTriggerStage() != pb.GraphTriggerStage_GRAPH_TRIGGER_STAGE_AUTHORIZED {
		t.Errorf("opened, not confirmed: %v", a)
	}
	if !gapNamed(g, "CONSEQUENCE_UNKNOWN") {
		t.Error("a consequence the rule could not rule out is no gap")
	}
	for _, e := range edgesOf(g, "gap") {
		if e.GetTo().GetId() == opened.String() && e.GetProvenance() == "NO_GRANT_RECORDED" {
			t.Errorf("the opened consequence is no decision to authorize: %v", e)
		}
	}
	for _, e := range g.GetEdges() {
		if e.GetObserveTime() == nil || e.GetFreshness() == "" || e.GetProvenance() == "" || e.GetAssurance() == "" {
			t.Errorf("an edge without source, time or freshness: %v", e)
		}
		if e.GetStatus() == pb.GraphEdgeStatus_GRAPH_EDGE_STATUS_UNSPECIFIED {
			t.Errorf("an edge without a state: %v", e)
		}
	}
}

// TestT239_AnActionWithNoRecordsShowsGapsNotCauses: the fixture's bare
// dispatch has no grant, receipt or effect: no causal link is drawn, each
// absence is a gap, and collapsing keeps them all.
// Covers: F279, F294
func TestT239_AnActionWithNoRecordsShowsGapsNotCauses(t *testing.T) {
	w := newWorld(t, billing.Team)
	scope := &pb.GraphScope{Type: "run", Id: w.o.Run.String()}
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_CAUSAL, Scope: scope, Collapse: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"authorized", "approved", "custody", "effect", "triggered"} {
		if got := edgesOf(g, kind); len(got) != 0 {
			t.Errorf("a %s link with no evidence: %v", kind, got)
		}
	}
	for _, missing := range []string{"NO_DECISION_RECEIPT", "NO_EXECUTION_RECEIPT", "NO_EFFECT_RECEIPT"} {
		if !gapNamed(g, missing) {
			t.Errorf("no gap %s in %v", missing, g.GetEdges())
		}
	}
}

// TestF276_TheChangeGraphComparesBeforeAndAfter: a revision that narrows a
// grant and a revocation read as operations added, removed and kept, from
// the stored bounds, scoped to what the viewer may see.
// Covers: F274, F276
func TestF276_TheChangeGraphComparesBeforeAndAfter(t *testing.T) {
	w := newWorld(t, billing.Team)
	grant := w.o.Grant(t, w.o.Agent, 0, "", "payments.refund.get", "payments.refund.create")
	w.o.Exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by) VALUES ($1, $2, $3, 2, now() - interval '1 hour',
		now() + interval '1 day', $4, '\x7b7d', '\x7b7d', 0, 0, 0, false, 'test')`,
		w.o.Org, ids.NewV7(), grant, []byte(`{"operations":["payments.refund.get","payments.charge.get"]}`))
	w.o.D.AdminExec(t, `UPDATE pc.grants SET current_revision = 2 WHERE id = $1`, grant)
	revoked := w.o.Grant(t, w.o.Agent, 0, "", "wiki.page.read")
	w.o.Revoke(t, revoked)
	hidden := w.o.Grant(t, w.o.Other, 0, "", "secret.thing.read")

	scope := &pb.GraphScope{Type: "agent", Id: w.o.Agent.String()}
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_CHANGE, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	change := func(grant ids.UUID, op string, want pb.GraphEdgeChange) {
		t.Helper()
		if !slices.ContainsFunc(edgesOf(g, "allows"), func(e *pb.GraphEdge) bool {
			return e.GetFrom().GetId() == grant.String() && e.GetTo().GetId() == op && e.GetChange() == want && e.GetRevision() >= 1 &&
				e.GetEvidenceRef() != ""
		}) {
			t.Errorf("%s of %s not %s in %v", op, grant, want, g.GetEdges())
		}
	}
	change(grant, "payments.refund.get", pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_KEPT)
	change(grant, "payments.refund.create", pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_REMOVED)
	change(grant, "payments.charge.get", pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_ADDED)
	change(revoked, "wiki.page.read", pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_REMOVED)
	team, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_CHANGE, Scope: &pb.GraphScope{Type: "agent", Id: w.o.Other.String()}})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range team.GetEdges() {
		if e.GetFrom().GetId() == hidden.String() || e.GetTo().GetId() == "secret.thing.read" {
			t.Errorf("a hidden agent's change: %v", e)
		}
	}
}

// TestT238_AGraphLabelNeverNamesAHiddenRecord: a viewer who may read an
// agent gets its name on the node and on the table's edges; a viewer
// scoped to one team gets no label from the hidden agent, or from a
// connection it may not read across the organization. Stored markup never
// reaches a label.
// Covers: F290, F298, F300
func TestT238_AGraphLabelNeverNamesAHiddenRecord(t *testing.T) {
	w := newWorld(t, billing.Team)
	o := w.o
	o.D.AdminExec(t, `UPDATE pc.agents SET name = 'visible-agent' WHERE id = $1`, o.Agent)
	o.D.AdminExec(t, `UPDATE pc.agents SET name = 'hidden-agent' WHERE id = $1`, o.Other)
	o.D.AdminExec(t, `UPDATE pc.connections SET name = 'secret-connection' WHERE id = $1`, o.Conn)
	label := func(g *pb.GetGraphResponse, id string) string {
		i := slices.IndexFunc(g.GetNodes(), func(n *pb.GraphNode) bool { return n.GetId() == id })
		if i < 0 {
			return ""
		}
		return g.GetNodes()[i].GetLabel()
	}

	scope := &pb.GraphScope{Type: "agent", Id: o.Agent.String()}
	org, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_EXPOSURE, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if got := label(org, o.Agent.String()); got != "visible-agent" {
		t.Errorf("agent label %q", got)
	}
	if got := label(org, o.Conn.String()); got != "secret-connection" {
		t.Errorf("connection label for an org viewer: %q", got)
	}
	table, err := w.g.ListGraphEdges(w.org, &pb.ListGraphEdgesRequest{Mode: pb.GraphMode_GRAPH_MODE_EXPOSURE, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(table.GetEdges(), func(e *pb.GraphEdge) bool { return e.GetFrom().GetLabel() == "visible-agent" }) {
		t.Errorf("the table has no label: %v", table.GetEdges())
	}

	for _, mode := range []pb.GraphMode{pb.GraphMode_GRAPH_MODE_ACTIVITY, pb.GraphMode_GRAPH_MODE_CAUSAL, pb.GraphMode_GRAPH_MODE_AUTHORITY, pb.GraphMode_GRAPH_MODE_EXPOSURE} {
		g, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{Mode: mode, Scope: scope})
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range g.GetNodes() {
			if strings.Contains(n.GetLabel(), "hidden-agent") || strings.Contains(n.GetLabel(), "secret-connection") {
				t.Errorf("%s: a hidden name in a label: %v", mode, n)
			}
		}
		if mode == pb.GraphMode_GRAPH_MODE_AUTHORITY && label(g, o.Agent.String()) != "visible-agent" {
			t.Errorf("the team viewer lost its own agent's label: %v", g.GetNodes())
		}
	}

	o.D.AdminExec(t, `UPDATE pc.agents SET name = '<b>agent</b>' WHERE id = $1`, o.Agent)
	org, err = w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_EXPOSURE, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if got := label(org, o.Agent.String()); strings.ContainsAny(got, "<>") {
		t.Errorf("markup in a label: %q", got)
	}
}

// TestHR551_AConsequenceCutIsReportedAsACut: consequences past the read's
// bound leave the graph marked truncated, even when a filter leaves the
// graph far under its own limits (D32).
// Covers: F272, F281
func TestHR551_AConsequenceCutIsReportedAsACut(t *testing.T) {
	w := newWorld(t, billing.Team)
	// A decision holds at most 256 consequences, so 20 pass the read's bound.
	for range 20 {
		txn := w.o.Dispatch(t, "github.pull_request.merge")
		entry := ids.NewV7()
		w.o.Exec(t, `INSERT INTO pc.ledger_entries (org_id, id, kind, actor_type, actor_id, body)
			VALUES ($1, $2, 'decision.test', 'test', 'test', '\x7b7d')`, w.o.Org, entry)
		w.o.Exec(t, `INSERT INTO pc.decision_receipts (org_id, transaction_id, evaluation, receipt_jws, ledger_entry_id)
			VALUES ($1, $2, 1, 'x.y.z', $3)`, w.o.Org, txn, entry)
		w.o.D.AdminExec(t, `INSERT INTO pc.decision_consequences (org_id, transaction_id, evaluation, position, rule_id, operation, target_type,
			target_id, state, facts_digest, "unknown") SELECT $1, $2, 1, n, 'rule', 'github.deployment.trigger', 'repo', 'r', 'PREDICTED', $3, '[]'::jsonb
			FROM generate_series(0, 255) n`, w.o.Org, txn, "sha256:"+strings.Repeat("0", 64))
	}
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{
		Mode: pb.GraphMode_GRAPH_MODE_CAUSAL, Scope: &pb.GraphScope{Type: "run", Id: w.o.Run.String()},
		Filter: &pb.GraphFilter{Operations: []string{"github.pull_request.merge"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !g.GetTruncated() || len(g.GetEdges()) >= 2000 {
		t.Errorf("truncated %v with %d edges", g.GetTruncated(), len(g.GetEdges()))
	}
}

// TestHR551_AFilteredActionLeavesNoEdgeBehind: a decision or outcome filter
// applies to the transaction, so its receipts and consequences go with it.
// Covers: F272
func TestHR551_AFilteredActionLeavesNoEdgeBehind(t *testing.T) {
	w := newWorld(t, billing.Team)
	txn := w.o.Dispatch(t, "github.pull_request.merge")
	receipted(t, w, txn, w.o.Grant(t, w.o.Agent, 0, "", "github.*"))
	consequence(t, w, txn, 0, "PREDICTED", false)
	read := func(f *pb.GraphFilter) *pb.GetGraphResponse {
		t.Helper()
		g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{
			Mode: pb.GraphMode_GRAPH_MODE_CAUSAL, Scope: &pb.GraphScope{Type: "run", Id: w.o.Run.String()}, Filter: f,
		})
		if err != nil {
			t.Fatal(err)
		}
		return g
	}
	for _, f := range []*pb.GraphFilter{{Decisions: []string{"DENY"}}, {Outcomes: []string{"NONE_CONFIRMED"}}} {
		for _, e := range read(f).GetEdges() {
			if strings.Contains(e.GetFrom().GetId()+e.GetTo().GetId(), txn.String()) {
				t.Errorf("filter %v kept %v", f, e)
			}
		}
	}
	g := read(&pb.GraphFilter{Decisions: []string{"ALLOW"}, Outcomes: []string{"CONFIRMED"}})
	for _, kind := range []string{"authorized", "custody", "effect", "triggered"} {
		if len(edgesOf(g, kind)) == 0 {
			t.Errorf("the matching action lost its %s edge: %v", kind, g.GetEdges())
		}
	}
}

// TestF272_AFilterDrawsNoOrderTheRecordDoesNotHold: filtering out the
// action between two others leaves no then edge across it (D53).
// Covers: F272
func TestF272_AFilterDrawsNoOrderTheRecordDoesNotHold(t *testing.T) {
	w := newWorld(t, billing.Team)
	first := w.o.Dispatch(t, "github.pull_request.merge")
	middle := w.o.Dispatch(t, "github.pull_request.merge")
	last := w.o.Dispatch(t, "github.pull_request.merge")
	w.o.D.AdminExec(t, `UPDATE pc.transactions SET created_at = now() + (CASE id WHEN $1 THEN 1 WHEN $2 THEN 2 ELSE 3 END) * interval '1 millisecond',
		decision = CASE id WHEN $2 THEN 'DENY' ELSE decision END WHERE id IN ($1, $2, $3)`, first, middle, last)
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{
		Mode: pb.GraphMode_GRAPH_MODE_CAUSAL, Scope: &pb.GraphScope{Type: "run", Id: w.o.Run.String()},
		Filter: &pb.GraphFilter{Decisions: []string{"ALLOW"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range edgesOf(g, "then") {
		if e.GetFrom().GetId() == first.String() && e.GetTo().GetId() == last.String() {
			t.Errorf("an order the record does not hold: %v", e)
		}
	}
}

// TestF276_AnOperationUnderOtherBoundsReadsAsChanged: a revision that keeps
// an operation and narrows anything else does not read as KEPT (D37).
// Covers: F276
func TestF276_AnOperationUnderOtherBoundsReadsAsChanged(t *testing.T) {
	w := newWorld(t, billing.Team)
	grant := w.o.Grant(t, w.o.Agent, 0, "", "payments.refund.get")
	w.o.Exec(t, `INSERT INTO pc.grant_revisions (org_id, id, grant_id, revision, not_before, expires_at, bounds, requirements, limits,
		delegation_depth, max_children, min_attestation, widens, created_by) VALUES ($1, $2, $3, 2, now() - interval '1 hour',
		now() + interval '1 day', $4, '\x7b7d', '\x7b7d', 0, 0, 0, false, 'test')`,
		w.o.Org, ids.NewV7(), grant, []byte(`{"operations":["payments.refund.get"],"accounts":{"ids":["a1"]}}`))
	w.o.D.AdminExec(t, `UPDATE pc.grants SET current_revision = 2 WHERE id = $1`, grant)
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{
		Mode: pb.GraphMode_GRAPH_MODE_CHANGE, Scope: &pb.GraphScope{Type: "agent", Id: w.o.Agent.String()},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(edgesOf(g, "allows"), func(e *pb.GraphEdge) bool {
		return e.GetFrom().GetId() == grant.String() && e.GetRevision() == 2 && e.GetChange() == pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_CHANGED
	}) {
		t.Errorf("no CHANGED edge in %v", g.GetEdges())
	}
}

// respond records a response action and, when control is set, its control
// on the agent.
func respond(t *testing.T, w *world, incident ids.UUID, kind, status string, control bool) (action, placed ids.UUID) {
	t.Helper()
	o := w.o
	action, placed = ids.NewV7(), ids.NewV7()
	mode, settled := any(nil), any(nil)
	if kind == "CONTAIN" {
		mode = "DENY_ALL"
	}
	if status != "REQUESTED" && status != "PARTIAL" {
		settled = "now"
	}
	o.D.AdminExec(t, `INSERT INTO pc.response_actions (org_id, id, kind, scope_type, scope_id, control, reason, incident_id, actor, source, status, settled_at)
		VALUES ($1, $2, $3, 'agent', $4, $5, 'test', $6, 'user:test', 'PERSON', $7, CASE WHEN $8::text IS NULL THEN NULL ELSE now() END)`,
		o.Org, action, kind, o.Agent.String(), mode, incident, status, settled)
	if control {
		o.D.AdminExec(t, `INSERT INTO pc.containment_controls (org_id, id, action_id, scope_type, scope_id, control, reason, incident_id, created_by)
			VALUES ($1, $2, $3, 'agent', $4, 'DENY_ALL', 'test', $5, 'user:test')`, o.Org, placed, action, o.Agent.String(), incident)
	}
	return action, placed
}

// TestF276_TheChangeGraphShowsWhatResponseChanged: an incident and a
// restriction show their controls as before and after, an unconfirmed one
// says so, and a viewer who may not read them gets a gap whether the record
// exists or not, never an empty "nothing changed" (D38).
// Covers: F276, F299
func TestF276_TheChangeGraphShowsWhatResponseChanged(t *testing.T) {
	w := newWorld(t, billing.Team)
	o := w.o
	incident := ids.NewV7()
	_, held := respond(t, w, incident, "CONTAIN", "CONFIRMED", true)
	_, lifted := respond(t, w, incident, "CONTAIN", "CONFIRMED", true)
	// A control is lifted only by a decided restoration plan that lists it.
	plan := ids.NewV7()
	o.D.AdminExec(t, `INSERT INTO pc.restoration_plans (org_id, id, reason, state, requested_by) VALUES ($1, $2, 'test', 'STAGING', 'user:requester')`,
		o.Org, plan)
	o.D.AdminExec(t, `INSERT INTO pc.restoration_plan_controls (org_id, plan_id, control_id) VALUES ($1, $2, $3)`, o.Org, plan, lifted)
	o.D.AdminExec(t, `UPDATE pc.containment_controls SET lifted_at = now(), lifted_by = 'user:reviewer', restoration_id = $2 WHERE id = $1`, lifted, plan)
	partial, open := respond(t, w, incident, "CONTAIN", "PARTIAL", true)
	revoked, _ := respond(t, w, incident, "REVOKE", "CONFIRMED", false)
	failed, _ := respond(t, w, incident, "REVOKE", "FAILED", false)

	graph := func(ctx context.Context, typ, id string) (*pb.GetGraphResponse, error) {
		return w.g.GetGraph(ctx, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_CHANGE, Scope: &pb.GraphScope{Type: typ, Id: id}})
	}
	g, err := graph(w.org, "incident", incident.String())
	if err != nil {
		t.Fatal(err)
	}
	edge := func(ref string, change pb.GraphEdgeChange, status pb.GraphEdgeStatus) {
		t.Helper()
		if !slices.ContainsFunc(edgesOf(g, "changed"), func(e *pb.GraphEdge) bool {
			return e.GetEvidenceRef() == ref && e.GetChange() == change && e.GetStatus() == status && e.GetTo().GetId() == o.Agent.String()
		}) {
			t.Errorf("no %s %s %s in %v", ref, change, status, g.GetEdges())
		}
	}
	added, removed := pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_ADDED, pb.GraphEdgeChange_GRAPH_EDGE_CHANGE_REMOVED
	seen := pb.GraphEdgeStatus_GRAPH_EDGE_STATUS_OBSERVED
	enforced := pb.GraphEdgeStatus_GRAPH_EDGE_STATUS_ENFORCED
	edge("containment_control:"+held.String(), added, enforced)
	edge("containment_control:"+lifted.String(), added, seen)
	edge("containment_control:"+lifted.String(), removed, seen)
	edge("containment_control:"+open.String(), added, seen)
	edge("response_action:"+revoked.String(), added, enforced)
	unconfirmed := func(action ids.UUID) bool {
		return slices.ContainsFunc(edgesOf(g, "gap"), func(e *pb.GraphEdge) bool {
			return e.GetProvenance() == "CONTAINMENT_UNCONFIRMED" && e.GetFrom().GetId() == action.String()
		})
	}
	if !unconfirmed(partial) || !unconfirmed(failed) {
		t.Errorf("an unconfirmed action is no gap: %v", g.GetEdges())
	}
	for _, e := range edgesOf(g, "changed") {
		if e.GetEvidenceRef() == "response_action:"+failed.String() {
			t.Errorf("a failed action reads as a change: %v", e)
		}
	}

	g, err = graph(w.org, "restriction", partial.String())
	if err != nil {
		t.Fatal(err)
	}
	edge("containment_control:"+open.String(), added, seen)
	for _, e := range edgesOf(g, "changed") {
		if e.GetProvenance() == "containment_control" && e.GetEvidenceRef() != "containment_control:"+open.String() {
			t.Errorf("a restriction shows another's control: %v", e)
		}
	}
	if _, err := graph(w.org, "restriction", ids.NewV7().String()); !errors.Is(err, app.ErrNotFound) {
		t.Errorf("an unknown restriction: %v", err)
	}

	// The same answer for a record that exists and one that does not.
	for _, scope := range [][2]string{
		{"incident", incident.String()}, {"restriction", partial.String()}, {"restriction", ids.NewV7().String()},
	} {
		g, err := graph(w.team, scope[0], scope[1])
		if err != nil {
			t.Fatalf("%v: %v", scope, err)
		}
		if !gapNamed(g, "CONTROLS_NOT_READABLE") || slices.ContainsFunc(edgesOf(g, "changed"), func(e *pb.GraphEdge) bool {
			return e.GetProvenance() == "containment_control" || e.GetProvenance() == "response_action"
		}) {
			t.Errorf("%v, viewer without containment.read: %v", scope, g.GetEdges())
		}
	}
	// In every mode, and whatever the graph is narrowed to (D51, D54).
	for _, mode := range []pb.GraphMode{
		pb.GraphMode_GRAPH_MODE_ACTIVITY, pb.GraphMode_GRAPH_MODE_CAUSAL, pb.GraphMode_GRAPH_MODE_CHANGE,
		pb.GraphMode_GRAPH_MODE_AUTHORITY, pb.GraphMode_GRAPH_MODE_EXPOSURE,
	} {
		g, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{
			Mode: mode, Scope: &pb.GraphScope{Type: "restriction", Id: partial.String()},
			Filter: &pb.GraphFilter{AgentIds: []string{o.Agent.String()}},
		})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if !gapNamed(g, "CONTROLS_NOT_READABLE") {
			t.Errorf("%s, viewer without containment.read: %v", mode, g.GetEdges())
		}
	}
}

// TestF282_TheAuthorityGraphShowsGrantDelegation: a child grant links to the
// parent it narrows, and a viewer who may not see the parent's agent sees
// neither the link nor the parent.
// Covers: F282
func TestF282_TheAuthorityGraphShowsGrantDelegation(t *testing.T) {
	w := newWorld(t, billing.Team)
	o := w.o
	parent := o.Grant(t, o.Other, 1, "", "payments.*")
	child := o.Grant(t, o.Agent, 0, "", "payments.refund.get")
	o.D.AdminExec(t, `UPDATE pc.grants SET parent_id = $2, depth = 1 WHERE id = $1`, child, parent)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := app.Recompute(ctx, tx, "manual", 0)
		return err
	})
	scope := &pb.GraphScope{Type: "agent", Id: o.Agent.String()}
	g, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_AUTHORITY, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(edgesOf(g, "delegated"), func(e *pb.GraphEdge) bool {
		return e.GetFrom().GetId() == parent.String() && e.GetTo().GetId() == child.String() && e.GetEvidenceRef() == "grant:"+child.String()
	}) {
		t.Errorf("no delegation in %v", g.GetEdges())
	}
	g, err = w.g.GetGraph(w.team, &pb.GetGraphRequest{Mode: pb.GraphMode_GRAPH_MODE_AUTHORITY, Scope: scope})
	if err != nil {
		t.Fatal(err)
	}
	if len(edgesOf(g, "delegated")) != 0 || slices.ContainsFunc(g.GetNodes(), func(n *pb.GraphNode) bool { return n.GetId() == parent.String() }) {
		t.Errorf("a hidden parent reached the viewer: %v", g.GetEdges())
	}
}
