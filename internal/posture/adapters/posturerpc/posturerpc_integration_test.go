// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package posturerpc_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/adapters/posturerpc"
	"github.com/katocxl/pantherclaw/internal/posture/app"
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

func reconcile(t *testing.T, o *exposuretest.Org) {
	t.Helper()
	o.Tx(t, func(ctx context.Context, tx db.TenantTx) error {
		rec, err := exapp.Recompute(ctx, tx, "manual", 0)
		if err != nil {
			return err
		}
		_, err = app.Reconcile(ctx, tx, rec)
		return err
	})
}

// TestIntPostureRPCPermissionsAndLifecycle: a team-scoped responder reads
// and manages only its team's agent's findings (a finding with no agent
// needs org scope, and a hidden one is not found); a viewer reads nothing;
// below Business the queue is refused; no call remediates; and resolving
// an alert about the agent leaves its findings as they were (HR-255).
func TestIntPostureRPCPermissionsAndLifecycle(t *testing.T) {
	o := exposuretest.New(t)
	o.Grant(t, o.Agent, 0, "", "payments.*")
	o.Grant(t, o.Other, 0, "", "payments.*")
	o.Credential(t, "100 days")
	team := o.Claim(t, o.Agent)
	reconcile(t, o)
	h := posturerpc.New(&app.Service{Pool: o.P, Ents: edition(billing.Business)})
	org := as(o, td.RoleSecurityAdmin, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()})
	scoped := as(o, td.RoleResponder, td.Scope{Type: td.ScopeTeam, ID: team})
	viewer := as(o, td.RoleViewer, td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()})

	all, err := h.ListPostureFindings(org, &pb.ListPostureFindingsRequest{PageSize: 200})
	if err != nil || all.GetRestricted() {
		t.Fatal(err)
	}
	var mine, theirs, orgWide string
	for _, f := range all.GetFindings() {
		switch {
		case f.GetAgentId() == o.Agent.String() && f.GetKind() == "uncovered_path":
			mine = f.GetId()
		case f.GetAgentId() == o.Other.String():
			theirs = f.GetId()
		case f.GetAgentId() == "" && f.GetKind() == "stale_credential":
			orgWide = f.GetId()
		}
	}
	if mine == "" || theirs == "" || orgWide == "" {
		t.Fatalf("findings: %v", all.GetFindings())
	}
	part, err := h.ListPostureFindings(scoped, &pb.ListPostureFindingsRequest{PageSize: 200})
	if err != nil || !part.GetRestricted() {
		t.Fatalf("scoped list: %v", err)
	}
	for _, f := range part.GetFindings() {
		if f.GetAgentId() != o.Agent.String() {
			t.Fatalf("scoped caller read %s (%s)", f.GetKind(), f.GetAgentId())
		}
	}
	rc, err := h.ListPostureRootCauses(scoped, &pb.ListPostureRootCausesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	total := int32(0)
	for _, r := range rc.GetRootCauses() {
		total += r.GetFindings()
	}
	if int(total) != len(part.GetFindings()) {
		t.Fatalf("root causes count %d, readable findings %d", total, len(part.GetFindings()))
	}
	for _, hidden := range []string{theirs, orgWide} {
		if _, err := h.GetPostureFinding(scoped, &pb.GetPostureFindingRequest{Id: hidden}); !errors.Is(err, app.ErrFindingNotFound) {
			t.Fatalf("hidden finding: %v", err)
		}
		if _, err := h.AssignPostureFinding(scoped, &pb.AssignPostureFindingRequest{Id: hidden, OwnerUserId: o.User.String()}); !errors.Is(err, app.ErrFindingNotFound) {
			t.Fatalf("assigned a hidden finding: %v", err)
		}
	}
	if _, err := h.ListPostureFindings(viewer, &pb.ListPostureFindingsRequest{}); err == nil {
		t.Fatal("a viewer read the posture queue")
	}
	team2 := posturerpc.New(&app.Service{Pool: o.P, Ents: edition(billing.Team)})
	if _, err := team2.ListPostureFindings(org, &pb.ListPostureFindingsRequest{}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("team edition: %v", err)
	}

	if _, err := h.StartPostureTesting(scoped, &pb.StartPostureTestingRequest{Id: mine}); !errors.Is(err, app.ErrMove) {
		t.Fatalf("testing before assignment: %v", err)
	}
	if _, err := h.AssignPostureFinding(scoped, &pb.AssignPostureFindingRequest{Id: mine, OwnerUserId: ids.NewV7().String()}); !errors.Is(err, app.ErrOwner) {
		t.Fatalf("unknown owner: %v", err)
	}
	f, err := h.AssignPostureFinding(scoped, &pb.AssignPostureFindingRequest{Id: mine, OwnerUserId: o.User.String()})
	if err != nil || f.GetFinding().GetState() != pb.PostureState_POSTURE_STATE_ASSIGNED {
		t.Fatalf("assign: %v", err)
	}
	if _, err := h.AcceptPostureFinding(scoped, &pb.AcceptPostureFindingRequest{
		Id:    mine,
		Until: timestamppb.New(time.Now().Add(100 * 24 * time.Hour)), Reason: "accepted for the pilot",
	}); !errors.Is(err, app.ErrAccept) {
		t.Fatalf("100-day acceptance: %v", err)
	}

	// Resolving an alert about the agent touches no finding.
	o.Exec(t, `INSERT INTO pc.alerts (org_id, id, source, title, severity, attention, basis, subjects, dedupe_key, first_seen, last_seen)
		VALUES ($1, $2, 'detection', 'x', 'HIGH', 'ALERT', 'RULE_MATCH', $3, 'k', now(), now())`, o.Org, ids.NewV7(),
		[]byte(`[{"type":"agent","id":"`+o.Agent.String()+`"}]`))
	o.D.AdminExec(t, `UPDATE pc.alerts SET state = 'RESOLVED' WHERE org_id = $1`, o.Org)
	got, err := h.GetPostureFinding(org, &pb.GetPostureFindingRequest{Id: mine})
	if err != nil || got.GetFinding().GetState() != pb.PostureState_POSTURE_STATE_ASSIGNED {
		t.Fatalf("after the alert was resolved: %v %v", got.GetFinding().GetState(), err)
	}
	if n := len(got.GetEvents()); n != 2 { // OPENED, ASSIGNED
		t.Fatalf("history: %d events", n)
	}
}
