// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exposurerpc_test

import (
	"slices"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
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
