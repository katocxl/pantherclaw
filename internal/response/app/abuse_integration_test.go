// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"context"
	"errors"
	"testing"

	bdomain "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition bdomain.Edition

func (e edition) Current(context.Context) (bdomain.Entitlements, error) {
	return bdomain.Entitlements{Edition: bdomain.Edition(e)}, nil
}

func (w *world) caller(kind td.PrincipalKind, id ids.UUID, roles ...td.RoleName) context.Context {
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: w.org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject: td.Subject{Org: w.org, Principal: td.PrincipalRef{Kind: kind, ID: id}, Bindings: bs}, Credential: tenancy.CredAccessToken,
	})
}

// TestT110_ResponseAPIAbuseIsRefused: a SOAR integration asks only with
// response.request, only on Business, only for a narrow scope; it never
// contains through the people's API, never terminates and never asks for a
// restoration. A person without incident.respond contains nothing.
func TestT110_ResponseAPIAbuseIsRefused(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	r := &rapp.Response{C: w.c}
	sa := ids.NewV7()
	soar := w.caller(td.KindServiceAccount, sa, td.RoleSOARIntegration)
	run := reflexdomain.Subject{Type: reflexdomain.SubjectRun, ID: w.run.String()}
	req := rapp.SOARRequest{Key: "k1", Scope: run, Control: rdomain.DenyAll, Reason: "edr"}

	if _, _, err := r.RequestControl(soar, req); !errors.Is(err, rapp.ErrEdition) {
		t.Fatalf("SOAR on Community: %v", err)
	}
	w.c.Editions = edition(bdomain.Business)
	if _, _, err := r.RequestControl(w.caller(td.KindServiceAccount, sa), req); err == nil {
		t.Fatal("a SOAR request without response.request")
	}
	if _, _, err := r.RequestControl(soar, rapp.SOARRequest{Key: "k2", Scope: reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: w.alice.String()},
		Control: rdomain.DenyAll, Reason: "edr"}); !errors.Is(err, rapp.ErrSOARScope) {
		t.Fatalf("SOAR on a person: %v", err)
	}
	res, paths, err := r.RequestControl(soar, req)
	if err != nil || res.ActionID.IsZero() || len(paths) == 0 {
		t.Fatalf("SOAR on a run: %+v %v", res, err)
	}
	if _, err := r.Contain(soar, rapp.ContainInput{Scope: run, Control: rdomain.DenyAll, Reason: "x"}); !errors.Is(err, rapp.ErrHuman) {
		t.Fatalf("SOAR through Contain: %v", err)
	}
	if _, err := r.Terminate(soar, w.run, "x", nil, nil); !errors.Is(err, rapp.ErrHuman) {
		t.Fatalf("SOAR terminating: %v", err)
	}
	if _, _, err := r.RequestRestoration(soar, rapp.RestorationRequest{Controls: []ids.UUID{ids.NewV7()}, Reason: "x"}); !errors.Is(err, rapp.ErrHuman) {
		t.Fatalf("SOAR asking for a restoration: %v", err)
	}
	if _, err := r.Contain(w.caller(td.KindUser, w.alice, td.RoleViewer), rapp.ContainInput{Scope: run, Control: rdomain.DenyAll, Reason: "x"}); err == nil {
		t.Fatal("a viewer contained")
	}
	if _, err := r.Contain(w.caller(td.KindUser, w.alice, td.RoleResponder), rapp.ContainInput{
		Scope: reflexdomain.Subject{Type: reflexdomain.SubjectGrant, ID: w.grant.String()}, Control: rdomain.DenyAll, Reason: "x",
		SkipPreview: true, SkipReason: "emergency",
	}); !errors.Is(err, rapp.ErrStepUp) {
		t.Fatalf("an emergency skip without a step-up: %v", err)
	}
}

// TestT109_RestorationAbuseIsRefused: deciding a restoration needs
// agent.restore and a fresh security-key step-up; a staged plan needs Team;
// the requester never decides it.
func TestT109_RestorationAbuseIsRefused(t *testing.T) {
	w := newWorld(t, "PARTIAL")
	r := &rapp.Response{C: w.c}
	_, control := w.containAgent()
	alice := w.caller(td.KindUser, w.alice, td.RoleResponder)
	if _, _, err := r.RequestRestoration(alice, rapp.RestorationRequest{
		Controls: []ids.UUID{control}, Reason: "x", Stages: []rapp.StageSpec{{Controls: []ids.UUID{control}}},
	}); !errors.Is(err, rapp.ErrStagedEdition) {
		t.Fatalf("a staged plan on Community: %v", err)
	}
	plan, _, err := r.RequestRestoration(alice, rapp.RestorationRequest{Controls: []ids.UUID{control}, Reason: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := r.DecideRestoration(w.caller(td.KindUser, ids.NewV7(), td.RoleApprover), plan, true); err == nil {
		t.Fatal("an approver without agent.restore decided")
	}
	if _, _, err := r.DecideRestoration(w.caller(td.KindUser, ids.NewV7(), td.RoleResponder), plan, true); !errors.Is(err, rapp.ErrStepUp) {
		t.Fatalf("no step-up: %v", err)
	}
	if _, _, err := r.DecideRestoration(w.caller(td.KindServiceAccount, ids.NewV7(), td.RoleSOARIntegration), plan, true); err == nil {
		t.Fatal("a service account decided")
	}
	if err := w.tx(func(ctx context.Context, tx db.TenantTx) error {
		_, _, err := w.c.DecideRestorationIn(ctx, tx, plan, w.alice, true)
		return err
	}); !errors.Is(err, rapp.ErrRequesterDecides) {
		t.Fatalf("the requester: %v", err)
	}
	if len(w.activeControls()) != 1 {
		t.Fatal("a refused restoration lifted the control")
	}
}
