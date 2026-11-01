// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"bytes"
	"context"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"google.golang.org/protobuf/types/known/timestamppb"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/investigations"
	"github.com/katocxl/pantherclaw/internal/operations"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
)

// TestE2E_M22_GraphData is M22's data exit journey (G0 M22 D19). A refund
// goes through the real gateway; a signed-in admin then reads, through the
// server, a causal graph whose links name the stored receipts of that refund,
// gaps where a record is missing, lanes, coverage edges with their reasons, and
// metrics that drill to their records or say they have none. The same admin
// then rotates a credential over the RPCs, which refuse what needs a step-up
// (T-240), and reads scan state, ticket links, the sync log and model usage
// (G0 M22 D6-D8).
//
// Covers: F272, F277, F284, F289, F293, F301, F424, F831, F832, F833, F834
func TestE2E_M22_GraphData(t *testing.T) {
	p := inProcessIdP(t)
	s := start(t, options{budget: "1000.00", billing: true, people: &p, github: true, jira: true, modelDrafting: true})
	activePlan(t, s.pool, s.org)
	code, r := s.refund(t, ids.NewV7(), "30.00")
	if code != http.StatusOK || r.Outcome != "ACCEPTED" {
		t.Fatalf("refund: %d %+v", code, r)
	}
	s.eventually(t, "CONFIRMED", "SELECT coalesce(effect_state, '') FROM pc.transactions WHERE id = $1", r.TransactionID)
	rc := s.m22Admin(t, p)
	t.Run("the causal graph names each link's receipt and marks what is missing", func(t *testing.T) { s.m22Causal(t, rc, r.TransactionID) })
	t.Run("the timeline's events carry their read class and the run's lanes", func(t *testing.T) { s.m22Timeline(t, rc, r.TransactionID) })
	t.Run("the coverage graph's edges say why, when and until when", func(t *testing.T) { s.m22Coverage(t, rc, r.TransactionID) })
	t.Run("a metric drills to its records or says it has none", func(t *testing.T) { s.m22Metrics(t, rc) })
	t.Run("a rotation runs over the RPCs and only a step-up activates or rolls back", func(t *testing.T) { s.m22Rotation(t, rc) })
	t.Run("an agent's scan state sums its findings", func(t *testing.T) { s.m22ScanState(t, rc) })
	t.Run("a case's tickets and the sync log read back", func(t *testing.T) { s.m22Tickets(t, rc) })
	t.Run("model drafts and usage read back as counts", func(t *testing.T) { s.m22ModelReads(t, rc) })
}

// m22Admin signs in a security admin, auditor, gateway admin and responder of
// the stack's org.
func (s *stack) m22Admin(t *testing.T, p idp) *connect.Client {
	t.Helper()
	org := s.org.String()
	var out, errb bytes.Buffer
	if code := runServerCmd(&out, &errb, "org", "admin-invite", "--config", s.serverCfg, "--org", org); code != 0 {
		t.Fatalf("org admin-invite: %d %s", code, errb.String())
	}
	people := &m2Stack{url: s.apiURL, cfg: s.serverCfg, idp: p}
	admin := people.user(t, "m22-admin", "m22-admin@example.test")
	admin.login(t, org, pciToken.FindStringSubmatch(out.String())[1])
	id := s.row(t, "SELECT id::text FROM pc.users WHERE subject = 'm22-admin'")
	for _, role := range []string{"security_admin", "auditor", "gateway_admin", "responder"} {
		if code, o, e := admin.pclaw(t, "role", "bind", "--role", role, "--user", id); code != 0 {
			t.Fatalf("role bind %s: %d %s %s", role, code, o, e)
		}
	}
	admin.login(t, org, "")
	return connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, admin)},
	}, s.apiURL))
}

func (s *stack) m22Causal(t *testing.T, rc *connect.Client, txn string) {
	ctx := context.Background()
	run := s.row(t, "SELECT run_id::text FROM pc.transactions WHERE id = $1", txn)
	// A second action of the run has no record behind it.
	bare := ids.NewV7()
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
			gateway_id, connection_id, mode) SELECT org_id, $2, run_id, $3, action_hash, operation, 'ALLOW', 'OK', gateway_id, connection_id, mode
			FROM pc.transactions WHERE id = $1`, txn, bare, ids.NewV7())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	g, err := pantherclawv1connect.NewGraphServiceClient(rc).GetGraph(ctx, &pantherclawv1.GetGraphRequest{
		Mode: pantherclawv1.GraphMode_GRAPH_MODE_CAUSAL, Scope: &pantherclawv1.GraphScope{Type: "run", Id: run}, Collapse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	link := func(kind, prefix string) {
		t.Helper()
		if !slices.ContainsFunc(g.GetEdges(), func(e *pantherclawv1.GraphEdge) bool {
			return e.GetKind() == kind && strings.Contains(e.GetTo().GetId(), txn) && strings.HasPrefix(e.GetEvidenceRef(), prefix)
		}) {
			t.Errorf("no %s link with %s in %v", kind, prefix, g.GetEdges())
		}
	}
	link("authorized", "decision_receipt:"+txn)
	link("custody", "execution_receipt:")
	link("effect", "effect_receipt:"+txn)
	if !slices.ContainsFunc(g.GetEdges(), func(e *pantherclawv1.GraphEdge) bool {
		return e.GetKind() == "gap" && strings.Contains(e.GetFrom().GetId()+e.GetTo().GetId(), bare.String())
	}) {
		t.Errorf("the bare action has no gap: %v", g.GetEdges())
	}
	for _, e := range g.GetEdges() {
		if e.GetKind() != "gap" && strings.Contains(e.GetTo().GetId(), bare.String()) && e.GetEvidenceRef() != "" {
			t.Errorf("a link with no record: %v", e)
		}
		if e.GetObserveTime() == nil || e.GetFreshness() == "" || e.GetProvenance() == "" {
			t.Errorf("an edge without its source: %v", e)
		}
	}
}

func (s *stack) m22Timeline(t *testing.T, rc *connect.Client, txn string) {
	ctx := context.Background()
	run := s.row(t, "SELECT run_id::text FROM pc.transactions WHERE id = $1", txn)
	if err := s.pool.InTenantTx(ctx, s.org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := tx.Exec(ctx, "UPDATE pc.transactions SET read_class = 'pii' WHERE id = $1", txn)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	// A child run of its own, with one action.
	child, inner := ids.NewV7().String(), ids.NewV7().String()
	instance := s.row(t, `SELECT i.id::text FROM pc.agent_instances i JOIN pc.runs r ON r.org_id = i.org_id AND r.agent_id = i.agent_id
		WHERE r.id = $1 AND i.state = 'ADMITTED' LIMIT 1`, run)
	s.db.AdminExec(t, `INSERT INTO pc.runs (org_id, id, agent_id, environment_id, launcher_instance_id, principal_user_id, principal_sa_id,
		principal_source, parent_run_id, depth, expires_at) SELECT org_id, $2, agent_id, environment_id, $3, principal_user_id, principal_sa_id,
		'parent_run', id, depth + 1, now() + interval '1 hour' FROM pc.runs WHERE id = $1`, run, child, instance)
	s.db.AdminExec(t, `INSERT INTO pc.transactions (org_id, id, run_id, action_id, action_hash, operation, decision, reason_code,
		gateway_id, connection_id, mode) SELECT org_id, $3, $2, $4, action_hash, operation, 'ALLOW', 'OK', gateway_id, connection_id, mode
		FROM pc.transactions WHERE id = $1`, txn, child, inner, ids.NewV7())
	tl, err := pantherclawv1connect.NewInvestigationServiceClient(rc).GetRunTimeline(ctx, &pantherclawv1.GetRunTimelineRequest{RunId: run})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(tl.GetEvents(), func(e *pantherclawv1.TimelineEvent) bool { return e.GetReadClass() == "pii" }) {
		t.Errorf("no read class: %v", tl.GetEvents())
	}
	lane := func(tl *pantherclawv1.GetRunTimelineResponse) bool {
		return slices.ContainsFunc(tl.GetLanes(), func(l *pantherclawv1.TimelineLane) bool {
			return l.GetRunId() == child && !l.GetEventsNotLoaded() && !l.GetEventsTruncated() && slices.ContainsFunc(l.GetEvents(),
				func(e *pantherclawv1.TimelineEvent) bool {
					return e.GetTransactionId() == inner && e.GetKind() == investigations.EventDecision
				})
		})
	}
	if !lane(tl) {
		t.Errorf("no lane of the child with its action: %v", tl.GetLanes())
	}
}

func (s *stack) m22Coverage(t *testing.T, rc *connect.Client, txn string) {
	ctx := context.Background()
	c := pantherclawv1connect.NewCoverageServiceClient(rc)
	conn := s.row(t, "SELECT connection_id::text FROM pc.transactions WHERE id = $1", txn)
	agent := s.row(t, "SELECT r.agent_id::text FROM pc.runs r JOIN pc.transactions t ON t.run_id = r.id WHERE t.id = $1", txn)
	// Coverage reads traffic a minute behind the clock.
	s.db.AdminExec(t, "UPDATE pc.transactions SET created_at = now() - interval '2 minutes' WHERE org_id = $1", s.org)
	if _, err := c.Reassess(ctx, &pantherclawv1.ReassessRequest{ConnectionId: conn}); err != nil {
		t.Fatal(err)
	}
	g, err := c.GetCoverageGraph(ctx, &pantherclawv1.GetCoverageGraphRequest{AgentId: agent})
	if err != nil {
		t.Fatal(err)
	}
	if len(g.GetEdges()) == 0 {
		t.Fatalf("no edges: %v", g)
	}
	for _, e := range g.GetEdges() {
		if e.GetReason() == "" || e.GetLastCheckedAt() == nil {
			t.Errorf("an edge with no reason or check time: %v", e)
		}
	}
	if !slices.ContainsFunc(g.GetNodes(), func(n *pantherclawv1.CoverageGraphNode) bool { return n.GetEffectGroup() != "" }) {
		t.Errorf("no effect group: %v", g.GetNodes())
	}
}

func (s *stack) m22Metrics(t *testing.T, rc *connect.Client) {
	ctx := context.Background()
	collector := &operations.Collector{Pool: s.pool, Ents: m21Edition(billing.Business), Failures: &failures.Sink{}}
	if _, err := collector.Collect(ctx, s.org); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour)
	m, err := pantherclawv1connect.NewOperationsServiceClient(rc).GetMetrics(ctx, &pantherclawv1.GetMetricsRequest{
		StartTime: timestamppb.New(now.Add(-time.Hour)), EndTime: timestamppb.New(now),
	})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, series := range m.GetSeries() {
		seen[series.GetMetric()] = true
		for _, p := range series.GetPoints() {
			// A restricted point says restricted, not that no search exists.
			if p.GetNoDrill() != (p.GetState() != string(operations.PointRestricted) && p.GetDrillQuery() == nil && p.GetDrillBuiltin() == nil) {
				t.Errorf("%s/%s: %v", series.GetMetric(), series.GetDimension(), p)
			}
		}
	}
	for _, metric := range []string{operations.MetricCoverageStale, operations.MetricBypassByOwner} {
		if !seen[metric] {
			t.Errorf("no series %s", metric)
		}
	}
}
