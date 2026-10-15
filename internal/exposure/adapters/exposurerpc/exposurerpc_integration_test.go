// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package exposurerpc_test

import (
	"context"
	"errors"
	"slices"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/adapters/exposurerpc"
	"github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e)}, nil
}

func as(o *exposuretest.Org, role td.RoleName, scope td.Scope) context.Context {
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{
			Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
			Bindings: []td.Binding{{Role: role, Scope: scope}},
		},
		Credential: tenancy.CredAccessToken,
	})
}

type world struct {
	o              *exposuretest.Org
	h              *exposurerpc.Handler
	g              *exposurerpc.Graphs
	org, team, bad context.Context
}

func newWorld(t *testing.T, ed billing.Edition) *world {
	t.Helper()
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 1, "", "payments.*")
	o.Grant(t, o.Other, 0, "", "payments.*")
	o.Credential(t, "1 day")
	o.Dispatch(t, "payments.refund.get")
	team := o.Claim(t, o.Agent)
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		_, err := app.Recompute(ctx, tx, "manual", 0)
		return err
	})
	h, g := exposurerpc.New(&app.Service{Pool: o.P, Ents: edition(ed)})
	return &world{
		o: o, h: h, g: g,
		org:  as(o, td.RoleSecurityAdmin, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}),
		team: as(o, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: team}),
		bad:  as(o, td.RoleViewer, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}),
	}
}

func agents(rs []*pb.ExposureRight) []string {
	var out []string
	for _, r := range rs {
		if !slices.Contains(out, r.GetAgentId()) {
			out = append(out, r.GetAgentId())
		}
	}
	slices.Sort(out)
	return out
}

// TestHR254_GraphsAndTablesFilterByPermission (T-042, graph half): a
// responder bound to one team reads only that team's agent in the
// exposure table, the matrix, the ranking and every graph and its edge
// table; the hidden agent is in no node, edge or count, credential rights
// (held by no agent) need org scope, and the response says it is
// restricted because of the caller's scope. The org-wide caller sees both
// agents, and counts exactly the difference. Historical edges never count
// as current authority.
func TestHR254_GraphsAndTablesFilterByPermission(t *testing.T) {
	w := newWorld(t, billing.Team)
	mine, hidden := w.o.Agent.String(), w.o.Other.String()

	all, err := w.h.GetExposure(w.org, &pb.GetExposureRequest{PageSize: 200})
	if err != nil {
		t.Fatal(err)
	}
	if got := agents(all.GetRights()); !slices.Contains(got, mine) || !slices.Contains(got, hidden) || !slices.Contains(got, "") ||
		all.GetRestricted() {
		t.Fatalf("org view: %v restricted=%v", got, all.GetRestricted())
	}
	scoped, err := w.h.GetExposure(w.team, &pb.GetExposureRequest{PageSize: 200})
	if err != nil {
		t.Fatal(err)
	}
	if got := agents(scoped.GetRights()); !slices.Equal(got, []string{mine}) || !scoped.GetRestricted() {
		t.Fatalf("team view: %v restricted=%v", got, scoped.GetRestricted())
	}
	if r, err := w.h.GetExposure(w.team, &pb.GetExposureRequest{AgentId: hidden}); err != nil || len(r.GetRights()) != 0 {
		t.Fatalf("asking for the hidden agent: %d %v", len(r.GetRights()), err)
	}

	m, err := w.h.GetReachMatrix(w.team, &pb.GetReachMatrixRequest{})
	if err != nil || !slices.Equal(m.GetAgentIds(), []string{mine}) {
		t.Fatalf("matrix agents: %v %v", m.GetAgentIds(), err)
	}
	rk, err := w.h.RankExposure(w.team, &pb.RankExposureRequest{})
	if err != nil || len(rk.GetAgents()) != 1 || rk.GetAgents()[0].GetAgentId() != mine {
		t.Fatalf("ranking: %v %v", rk.GetAgents(), err)
	}

	for _, mode := range []pb.GraphMode{pb.GraphMode_GRAPH_MODE_AUTHORITY, pb.GraphMode_GRAPH_MODE_EXPOSURE} {
		for _, scope := range []*pb.GraphScope{{Type: "agent", Id: hidden}, {Type: "resource", Id: "payments/payments.charge"}} {
			g, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{Mode: mode, Scope: scope, Collapse: true})
			if err != nil {
				t.Fatalf("%s %s: %v", mode, scope.GetType(), err)
			}
			for _, n := range g.GetNodes() {
				if n.GetId() == hidden || n.GetType() == "credential_holder" {
					t.Fatalf("%s %s: hidden node %v", mode, scope.GetType(), n)
				}
			}
			whole, err := w.g.GetGraph(w.org, &pb.GetGraphRequest{Mode: mode, Scope: scope, Collapse: true})
			if err != nil {
				t.Fatal(err)
			}
			if scope.GetType() == "agent" && (len(g.GetEdges()) != 0 || len(whole.GetEdges()) == 0) {
				t.Fatalf("%s: hidden agent's graph has %d edges (org: %d)", mode, len(g.GetEdges()), len(whole.GetEdges()))
			}
			table, err := w.g.ListGraphEdges(w.team, &pb.ListGraphEdgesRequest{Mode: mode, Scope: scope, Collapse: true, PageSize: 200})
			if err != nil || len(table.GetEdges()) != len(g.GetEdges()) || !table.GetRestricted() {
				t.Fatalf("%s %s table: %d vs %d %v", mode, scope.GetType(), len(table.GetEdges()), len(g.GetEdges()), err)
			}
			for k, n := range g.GetCurrent() {
				if n > whole.GetCurrent()[k] {
					t.Fatalf("%s: scoped count %s=%d exceeds the org's %d", mode, k, n, whole.GetCurrent()[k])
				}
			}
		}
	}
	// Activity of the hidden agent's run: nothing reaches the team caller.
	act, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{
		Mode:  pb.GraphMode_GRAPH_MODE_ACTIVITY,
		Scope: &pb.GraphScope{Type: "agent", Id: hidden},
	})
	if err != nil || len(act.GetEdges()) != 0 {
		t.Fatalf("hidden activity: %d %v", len(act.GetEdges()), err)
	}
	own, err := w.g.GetGraph(w.team, &pb.GetGraphRequest{
		Mode:  pb.GraphMode_GRAPH_MODE_ACTIVITY,
		Scope: &pb.GraphScope{Type: "run", Id: w.o.Run.String()},
	})
	if err != nil || len(own.GetEdges()) == 0 || own.GetCurrent()["acted"] != 0 {
		t.Fatalf("own activity: %d edges, current %v, %v", len(own.GetEdges()), own.GetCurrent(), err)
	}

	// A shared credential's dependents and previews span every agent: org
	// scope only.
	if _, err := w.h.ListCredentialDependents(w.team, &pb.ListCredentialDependentsRequest{ConnectionId: w.o.Conn.String()}); err == nil {
		t.Fatal("team caller listed a shared credential's dependents")
	}
	if d, err := w.h.ListCredentialDependents(w.org, &pb.ListCredentialDependentsRequest{ConnectionId: w.o.Conn.String()}); err != nil ||
		len(d.GetWorkloads()) != 3 {
		t.Fatalf("dependents: %v %v", d.GetWorkloads(), err)
	}
	preview := &pb.PreviewReductionRequest{
		Kind: "contain", Control: "DENY_ALL",
		Subjects: []*pb.ReductionSubject{{Type: "agent", Id: mine}},
	}
	if _, err := w.h.PreviewReduction(w.team, preview); err == nil {
		t.Fatal("team caller previewed over every agent")
	}
	if p, err := w.h.PreviewReduction(w.org, preview); err != nil || len(p.GetRemoved()) == 0 || len(p.GetRemaining()) == 0 {
		t.Fatalf("preview: %v", err)
	}
	if _, err := w.h.GetExposure(w.bad, &pb.GetExposureRequest{}); err == nil {
		t.Fatal("a viewer read exposure")
	}
}

// TestHR253_ExposureRPCKeepsViewsAndLabels: the three views come back
// apart, an unread credential scope is UNCERTAIN, each verb says why, and
// Community is refused.
func TestHR253_ExposureRPCKeepsViewsAndLabels(t *testing.T) {
	w := newWorld(t, billing.Team)
	r, err := w.h.GetExposure(w.org, &pb.GetExposureRequest{PageSize: 200})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[pb.ExposureView]bool{}
	for _, x := range r.GetRights() {
		seen[x.GetView()] = true
		if x.GetBasis() == "" {
			t.Fatalf("right without a basis: %v", x)
		}
		if x.GetResourceGroup() == "credential:payments" && x.GetLabel() != pb.ExposureLabel_EXPOSURE_LABEL_UNCERTAIN {
			t.Fatalf("unread credential scope: %v", x.GetLabel())
		}
	}
	if len(seen) != 3 {
		t.Fatalf("views: %v", seen)
	}
	if r.GetSnapshot().GetId() == "" || r.GetSnapshot().GetStale() {
		t.Fatalf("snapshot: %v", r.GetSnapshot())
	}
	c, _ := exposurerpc.New(&app.Service{Pool: w.o.P, Ents: edition(billing.Community)})
	if _, err := c.GetExposure(w.org, &pb.GetExposureRequest{}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("community: %v", err)
	}
}
