// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"slices"
	"testing"
	"time"

	exposure "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/posture/domain"
)

var now = time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)

func p(u ids.UUID) *ids.UUID { return &u }

func TestLifecycleTable(t *testing.T) {
	allowed := map[[2]domain.State]bool{}
	for _, m := range [][2]domain.State{
		{domain.Open, domain.Assigned},
		{domain.Open, domain.AcceptedTemporarily},
		{domain.Open, domain.EvidenceIncomplete},
		{domain.Open, domain.Remediated},
		{domain.Assigned, domain.Testing},
		{domain.Assigned, domain.Remediated},
		{domain.Testing, domain.Remediated},
		{domain.Testing, domain.Open},
		{domain.Remediated, domain.Open},
		{domain.AcceptedTemporarily, domain.Open},
		{domain.EvidenceIncomplete, domain.Open},
	} {
		allowed[m] = true
		if !domain.CanMove(m[0], m[1]) {
			t.Errorf("%s -> %s refused", m[0], m[1])
		}
	}
	for _, m := range [][2]domain.State{
		{domain.Open, domain.Testing},
		{domain.Remediated, domain.Assigned},
		{domain.AcceptedTemporarily, domain.Remediated},
		{domain.Open, domain.Open},
		{domain.Remediated, domain.AcceptedTemporarily},
	} {
		if domain.CanMove(m[0], m[1]) {
			t.Errorf("%s -> %s allowed", m[0], m[1])
		}
	}
	if domain.CheckAcceptance(now, now.Add(91*24*time.Hour), "risk accepted for the pilot") == nil ||
		domain.CheckAcceptance(now, now.Add(time.Hour), "short") == nil ||
		domain.CheckAcceptance(now, now.Add(-time.Hour), "risk accepted for the pilot") == nil ||
		domain.CheckAcceptance(now, now.Add(90*24*time.Hour), "risk accepted for the pilot") != nil {
		t.Fatal("acceptance bounds")
	}
}

func TestDeriveKinds(t *testing.T) {
	agent, conn, grant, cf := ids.NewV7(), ids.NewV7(), ids.NewV7(), ids.NewV7()
	r := func(view exposure.View, verb exposure.Verb, op string, cov exposure.Coverage, reasons ...string) exposure.Right {
		return exposure.Right{
			View: view, Label: exposure.Usable, Agent: p(agent), Connection: p(conn), Grant: p(grant),
			Operation: op, ResourceGroup: "payments/charge", Verb: verb, Coverage: cov, Reasons: reasons, Depth: 1,
		}
	}
	rights := []exposure.Right{
		r(exposure.Effective, exposure.VerbTransfer, "payments.refund.create", exposure.CoverageUnknown),
		r(exposure.Effective, exposure.VerbDelegate, "", exposure.CoveragePartial, exposure.ReasonDelegable),
		{
			View: exposure.Credential, Label: exposure.Usable, Connection: p(conn), ResourceGroup: "scope:administration",
			Verb: exposure.VerbUpdate, Coverage: exposure.CoverageUnknown,
		},
	}
	got := domain.Derive(domain.Inputs{
		Now: now, Rights: rights, Agents: []domain.Agent{{ID: agent}},
		Grants:           []domain.GrantInfo{{ID: grant, Unbounded: []string{"operations"}, CreatedAt: now.Add(-40 * 24 * time.Hour)}},
		Credentials:      []domain.CredentialInfo{{Connection: conn, Name: "payments", CreatedAt: now.Add(-100 * 24 * time.Hour)}},
		CoverageFindings: []domain.CoverageFinding{{ID: cf, Connection: p(conn), Subject: "App 7", Excess: []string{"administration:write"}, Severity: "high"}},
		Unverified:       map[string]bool{"payments.refund.create": true},
		Irreversible:     map[string]bool{"payments.refund.create": true},
	})
	var kinds []domain.Kind
	for _, c := range got {
		kinds = append(kinds, c.Kind)
		if len(c.Paths) == 0 {
			t.Errorf("%s has no paths", c.Kind)
		}
	}
	for _, k := range domain.Kinds {
		if !slices.Contains(kinds, k) {
			t.Errorf("kind %s not derived (got %v)", k, kinds)
		}
	}
	i := slices.IndexFunc(got, func(c domain.Candidate) bool { return c.Kind == domain.CredentialOverreach })
	if got[i].CoverageFinding == nil || *got[i].CoverageFinding != cf || len(got[i].Paths) != 1 ||
		got[i].Paths[0] != rights[2].PathKey() {
		t.Fatalf("overreach: %+v", got[i])
	}
	// Owned, enforced, verified, recent and used: nothing to find but the
	// stale credential and the overreach that come from elsewhere.
	rights[0].Coverage, rights[1].Coverage = exposure.CoverageEnforced, exposure.CoverageEnforced
	obs := rights[0]
	obs.View, obs.ObservedAt = exposure.Observed, &now
	got = domain.Derive(domain.Inputs{
		Now: now, Rights: append(rights, obs), Agents: []domain.Agent{{ID: agent, Owned: true}},
		Grants: []domain.GrantInfo{{ID: grant, CreatedAt: now.Add(-40 * 24 * time.Hour)}},
	})
	if len(got) != 0 {
		t.Fatalf("clean posture: %+v", got)
	}
}

// TestHR255_RemediatedOnlyWhenEveryPathIsGone: a finding no longer derived
// is REMEDIATED only when none of its affected paths is reachable; a
// truncated snapshot or one that could not read the connection gives
// EVIDENCE_INCOMPLETE; a remediated finding found again reopens; an expired
// acceptance reopens.
func TestHR255_RemediatedOnlyWhenEveryPathIsGone(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	right := exposure.Right{
		View: exposure.Effective, Label: exposure.Usable, Agent: p(agent), Connection: p(conn),
		Operation: "x.y", ResourceGroup: "g", Verb: exposure.VerbUpdate, Coverage: exposure.CoverageUnknown,
	}
	cand := domain.Candidate{
		Kind: domain.UncoveredPath, RootCause: "connection:" + conn.String(), Agent: p(agent),
		Paths: []string{right.PathKey(), "other|path"},
	}
	f := domain.Finding{
		ID: ids.NewV7(), Kind: cand.Kind, Fingerprint: cand.Fingerprint(), State: domain.Open,
		Paths: cand.Paths, Connection: p(conn),
	}

	acts := domain.Reconcile([]domain.Finding{f}, nil, domain.Snapshot{Now: now, Rights: []exposure.Right{right}})
	if len(acts) != 0 {
		t.Fatalf("a path still reachable: %+v", acts)
	}
	// Reachable only as history: remediated.
	hist := right
	hist.View = exposure.Observed
	acts = domain.Reconcile([]domain.Finding{f}, nil, domain.Snapshot{Now: now, Rights: []exposure.Right{hist}})
	if len(acts) != 1 || acts[0].Kind != domain.ActRemediate {
		t.Fatalf("gone: %+v", acts)
	}
	expired := right
	expired.Label = exposure.Expired
	if acts = domain.Reconcile([]domain.Finding{f}, nil, domain.Snapshot{Now: now, Rights: []exposure.Right{expired}}); len(acts) != 1 ||
		acts[0].Kind != domain.ActRemediate {
		t.Fatalf("expired right: %+v", acts)
	}
	for _, s := range []domain.Snapshot{
		{Now: now, Truncated: true},
		{Now: now, Gaps: []string{"PACKAGE_UNKNOWN:" + conn.String()}},
		{Now: now, Gaps: []string{"POLICY_UNKNOWN"}},
	} {
		if acts = domain.Reconcile([]domain.Finding{f}, nil, s); len(acts) != 1 || acts[0].Kind != domain.ActIncomplete {
			t.Fatalf("incomplete snapshot %+v: %+v", s, acts)
		}
	}
	f.State = domain.Remediated
	if acts = domain.Reconcile([]domain.Finding{f}, []domain.Candidate{cand}, domain.Snapshot{Now: now}); len(acts) != 1 ||
		acts[0].Kind != domain.ActReopen {
		t.Fatalf("found again: %+v", acts)
	}
	until := now.Add(-time.Minute)
	f.State, f.AcceptedUntil = domain.AcceptedTemporarily, &until
	if acts = domain.Reconcile([]domain.Finding{f}, []domain.Candidate{cand}, domain.Snapshot{Now: now}); len(acts) != 1 ||
		acts[0].Kind != domain.ActExpire {
		t.Fatalf("acceptance expired: %+v", acts)
	}
	later := now.Add(time.Hour)
	f.AcceptedUntil = &later
	if acts = domain.Reconcile([]domain.Finding{f}, nil, domain.Snapshot{Now: now}); len(acts) != 0 {
		t.Fatalf("accepted and gone moves only at expiry: %+v", acts)
	}
	if acts = domain.Reconcile(nil, []domain.Candidate{cand}, domain.Snapshot{Now: now}); len(acts) != 1 || acts[0].Kind != domain.ActOpen {
		t.Fatalf("new: %+v", acts)
	}
}

// TestReconcilePerKind: a cause-type finding no longer derived is
// remediated on a complete snapshot even while its subject keeps reach; a
// reach-type one is not; a finding with paths beyond the kept ones, or a
// snapshot whose gaps overflowed, is evidence-incomplete (D63 M1, L3, L4).
func TestReconcilePerKind(t *testing.T) {
	agent, conn := ids.NewV7(), ids.NewV7()
	right := exposure.Right{
		View: exposure.Effective, Label: exposure.Usable, Agent: p(agent), Connection: p(conn),
		Operation: "x.y", ResourceGroup: "g", Verb: exposure.VerbUpdate, Coverage: exposure.CoverageUnknown,
	}
	snap := domain.Snapshot{Now: now, Rights: []exposure.Right{right}}
	cause := domain.Finding{
		ID: ids.NewV7(), Kind: domain.UnownedAgent, Fingerprint: []byte{1}, State: domain.Open,
		Paths: []string{right.PathKey()},
	}
	reach := domain.Finding{
		ID: ids.NewV7(), Kind: domain.UncoveredPath, Fingerprint: []byte{2}, State: domain.Open,
		Paths: []string{right.PathKey()},
	}
	acts := domain.Reconcile([]domain.Finding{cause, reach}, nil, snap)
	if len(acts) != 1 || acts[0].Finding.ID != cause.ID || acts[0].Kind != domain.ActRemediate {
		t.Fatalf("per kind: %+v", acts)
	}
	if acts = domain.Reconcile([]domain.Finding{cause}, nil, domain.Snapshot{Now: now, Gaps: []string{"MORE_GAPS"}}); len(acts) != 1 ||
		acts[0].Kind != domain.ActIncomplete {
		t.Fatalf("gaps overflowed: %+v", acts)
	}
	reach.PathsTruncated = true
	if acts = domain.Reconcile([]domain.Finding{reach}, nil, domain.Snapshot{Now: now}); len(acts) != 1 || acts[0].Kind != domain.ActIncomplete {
		t.Fatalf("truncated paths: %+v", acts)
	}
	for _, k := range domain.Kinds {
		want := k == domain.UnownedAgent || k == domain.UnverifiedSensitiveTool || k == domain.StaleCredential
		if k.CauseType() != want {
			t.Errorf("%s cause-type %v", k, !want)
		}
	}
}
