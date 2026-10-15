// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration && sandbox

package e2e

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"testing"
	"time"

	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	capp "github.com/katocxl/pantherclaw/internal/cases/app"
	cdomain "github.com/katocxl/pantherclaw/internal/cases/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestE2E_M10_ContainEnforcedAgent is the CONFIRMED half of the M10 exit
// scenario (G0 M10 D40 step 3, D52, D58): every route of the agent reads
// ENFORCED from a real M9 sandbox closure, so a DENY_ALL on the agent
// (over the real server's ResponseService) reaches CONFIRMED once the
// gateway acknowledges the containment epoch, with no bypass route left.
// The case that links it (in-process, Team) then closes through CONTAINED:
// the closure rules accept a CONFIRMED containment, a fact, a disposition
// and an impact.
func TestE2E_M10_ContainEnforcedAgent(t *testing.T) {
	m := startM9(t)
	ctx := context.Background()
	number, head := m.mergeScope(t)
	if code, out, errs := m.sandbox(t, pclaw.Options{}, "merge", ghRepo, strconv.Itoa(number), head); code != 0 || !closurePassed.MatchString(out) {
		t.Fatalf("sandbox run: %d\n%s\n%s", code, out, errs)
	}
	m.enforcedSoon(t)
	if n := m.row(t, `SELECT count(*)::text FROM (SELECT DISTINCT ON (connection_id, operation) state FROM pc.coverage_snapshots
		WHERE agent_id = $1 ORDER BY connection_id, operation, id DESC) s WHERE state <> 'ENFORCED'`, m.agent); n != "0" {
		t.Fatalf("routes of the agent not ENFORCED: %s", n)
	}

	// Alice signs in again for a token that carries the roles startM9 bound.
	m.alice.login(t, m.org.String(), "")
	response := pantherclawv1connect.NewResponseServiceClient(connect.NewClient(connecthttp.NewTransport(&http.Client{
		Timeout: 30 * time.Second, Transport: keyBearer{bearerOf(t, m.alice)},
	}, m.apiURL)))
	aliceID := mustUUID(t, m.row(t, "SELECT id::text FROM pc.users WHERE subject = 'alice'"))
	alice := tapp.WithCaller(ctx, tapp.Caller{Subject: td.Subject{
		Org: m.org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: aliceID},
		Bindings: []td.Binding{{Role: td.RoleSecurityAdmin, Scope: td.Scope{Type: td.ScopeOrg, ID: m.org.UUID()}}},
	}, Credential: tapp.CredAccessToken})
	cases := &capp.Service{Pool: m.pool, Editions: ents{billing.Team}}
	k, err := cases.Open(alice, capp.OpenRequest{
		Title:    "Contain the coding agent",
		Subjects: []reflexdomain.Subject{{Type: reflexdomain.SubjectAgent, ID: m.agent}},
	})
	if err != nil {
		t.Fatal(err)
	}
	caseID := k.ID.String()
	contained, err := response.Contain(ctx, &pantherclawv1.ContainRequest{
		Scope: &pantherclawv1.ResponseSubject{Type: "agent", Id: m.agent}, Control: "DENY_ALL", Reason: "exit scenario", CaseId: &caseID,
	})
	if err != nil {
		t.Fatalf("Contain: %v", err)
	}
	var action *pantherclawv1.GetResponseActionResponse
	eventually(t, 2*time.Minute, "the containment to confirm", func() (bool, error) {
		a, err := response.GetResponseAction(ctx, &pantherclawv1.GetResponseActionRequest{ActionId: contained.GetActionId()})
		if err != nil {
			return false, err
		}
		action = a
		return a.GetAction().GetStatus() == "CONFIRMED", nil
	})
	if a := action.GetAction(); !a.GetMediatedConfirmed() || !a.GetFutureConfirmed() || slices.ContainsFunc(action.GetPaths(), func(p *pantherclawv1.ResponsePath) bool {
		return p.GetMaterial() && p.GetStatus() != "CONFIRMED"
	}) {
		t.Fatalf("a CONFIRMED action with an unconfirmed material path: %+v", action)
	}

	// The case closes through CONTAINED with the CONFIRMED action (HR-246).
	if _, err := cases.Append(alice, k.ID, cdomain.Draft{Kind: cdomain.KindState, State: cdomain.StateContained}); err != nil {
		t.Fatalf("CONTAINED with a CONFIRMED action: %v", err)
	}
	if _, err := cases.Append(alice, k.ID, cdomain.Draft{
		Kind: cdomain.KindFact, Text: "Every route of the agent is closed.",
		Basis: cdomain.BasisObserved, Evidence: []cdomain.EvidenceRef{{
			Kind: cdomain.EvidenceRun,
			ID:   mustUUID(t, m.row(t, "SELECT id::text FROM pc.runs WHERE agent_id = $1 ORDER BY created_at DESC LIMIT 1", m.agent)),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := cases.Append(alice, k.ID, cdomain.Draft{
		Kind: cdomain.KindState, State: cdomain.StateClosed,
		Disposition: cdomain.DispositionTruePositive, CaseImpact: cdomain.ImpactNoneFound,
	}); err != nil {
		t.Fatalf("close: %v", err)
	}
	if v, err := cases.Get(alice, k.ID, 0, 0); err != nil || v.Case.State != cdomain.StateClosed || v.Case.OperationalClosed == nil {
		t.Fatalf("the case: %+v %v", v.Case, err)
	}
}
