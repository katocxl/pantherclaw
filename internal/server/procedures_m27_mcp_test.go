// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect/v2"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/pclaw/selfmcp"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

func investigatorCaller(extra ...td.RoleName) tapp.Caller {
	org := ids.New[ids.Org]()
	s := td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindServiceAccount, ID: ids.NewV7()}}
	for _, r := range append([]td.RoleName{td.RoleInvestigator}, extra...) {
		s.Bindings = append(s.Bindings, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return tapp.Caller{Subject: s}
}

// passes runs the gate for one caller and procedure.
func passes(t *testing.T, c tapp.Caller, procedure string) (bool, tapp.Caller, error) {
	t.Helper()
	var got tapp.Caller
	ran := false
	g := testGate(billing.Team, nil)
	err := g.intercept(func(ctx context.Context, _ connect.Spec, _ connect.ServerStream) error {
		ran = true
		got, _ = tapp.CallerFrom(ctx)
		return nil
	})(tapp.WithCaller(context.Background(), c), connect.Spec{Procedure: procedure}, nil)
	return ran, got, err
}

// TestHR655_InvestigatorReachesOnlyTheFourReads walks every procedure the
// server serves: an Investigator gets through on the four reads, exactly,
// and each is a read. Everything else is refused, including what its
// permissions declare (the saved queries, model drafting, bundle export) and
// what any signed-in caller reaches.
// Covers: F946
func TestHR655_InvestigatorReachesOnlyTheFourReads(t *testing.T) {
	c := investigatorCaller()
	var reached []string
	for proc := range procedurePermissions {
		ran, _, err := passes(t, c, proc)
		if ran {
			reached = append(reached, proc)
			continue
		}
		if !errors.Is(err, errInvestigatorReads) {
			t.Errorf("%s: %v", proc, err)
		}
	}
	slices.Sort(reached)
	want := slices.Sorted(slices.Values(selfMCPReads))
	if !slices.Equal(reached, want) {
		t.Errorf("an Investigator reaches %v, want %v", reached, want)
	}
	for _, p := range reached {
		if procedureClass(p) != entitlements.ClassRead {
			t.Errorf("%s is %s, not a read", p, procedureClass(p))
		}
	}
}

// TestHR655_WritesItsPermissionsDeclareAreRefused names the procedures the
// gate exists for: without it, each of these admits an Investigator.
// Covers: F946
func TestHR655_WritesItsPermissionsDeclareAreRefused(t *testing.T) {
	c := investigatorCaller()
	for _, proc := range []string{
		pantherclawv1connect.SearchServiceSaveQueryProcedure,
		pantherclawv1connect.SearchServiceUpdateSavedQueryProcedure,
		pantherclawv1connect.SearchServiceDeleteSavedQueryProcedure,
		pantherclawv1connect.ModelServiceDraftQueryProcedure,
		pantherclawv1connect.EvidenceServiceExportBundleProcedure,
	} {
		if !procedureAdmits(c, proc) {
			t.Errorf("%s: its permission no longer admits the role; this list is stale", proc)
		}
		if ran, _, err := passes(t, c, proc); ran || !errors.Is(err, errInvestigatorReads) {
			t.Errorf("%s: ran=%v err=%v", proc, ran, err)
		}
	}
}

// TestHR656_ToolLayerAndServerListsMatch: the tool layer's allow-list is the
// server's, every entry is a read, and none takes a human-only permission.
// Covers: F946
func TestHR656_ToolLayerAndServerListsMatch(t *testing.T) {
	got := slices.Sorted(slices.Values(selfmcp.Procedures()))
	want := slices.Sorted(slices.Values(selfMCPReads))
	if !slices.Equal(got, want) {
		t.Fatalf("tool layer %v, server %v", got, want)
	}
	r, ok := td.LookupRole(td.RoleInvestigator)
	if !ok {
		t.Fatal("no Investigator role")
	}
	for _, p := range got {
		if procedureClass(p) != entitlements.ClassRead {
			t.Errorf("%s is %s, not a read", p, procedureClass(p))
		}
		if !r.Has(procedurePermissions[p]) {
			t.Errorf("%s needs %s, which the role does not hold", p, procedurePermissions[p])
		}
	}
}

// TestHR655_RoleDoesNotCountOutsideTheReads: a service account with a second
// role keeps what that role admits, and the call runs as if the Investigator
// binding were not there, so its org-wide evidence.read cannot widen it.
// Covers: F946
func TestHR655_RoleDoesNotCountOutsideTheReads(t *testing.T) {
	c := investigatorCaller(td.RoleScanner)
	proc := pantherclawv1connect.AgentServiceSubmitScanFindingsProcedure
	ran, got, err := passes(t, c, proc)
	if !ran || err != nil {
		t.Fatalf("ran=%v err=%v", ran, err)
	}
	if isInvestigator(got) || got.CanAnywhere(td.PermEvidenceRead) {
		t.Errorf("the handler sees %+v", got.Bindings)
	}
	if !isInvestigator(c) {
		t.Error("the gate changed the caller's bindings in place")
	}
	if ran, _, err := passes(t, c, pantherclawv1connect.EvidenceServiceExportBundleProcedure); ran || !errors.Is(err, errInvestigatorReads) {
		t.Errorf("bundle export: ran=%v err=%v", ran, err)
	}
}

// TestHR655_OtherCallersPassUntouched: the gate reads the role and nothing
// else, and a call with no caller (public, workload, gateway) goes on.
// Covers: F946
func TestHR655_OtherCallersPassUntouched(t *testing.T) {
	c := investigatorCaller()
	c.Bindings = []td.Binding{{Role: td.RoleViewer, Scope: c.Bindings[0].Scope}}
	if ran, _, err := passes(t, c, pantherclawv1connect.SearchServiceSaveQueryProcedure); !ran || err != nil {
		t.Errorf("a viewer: ran=%v err=%v", ran, err)
	}
	g := &selfMCPGate{}
	ran := false
	err := g.intercept(func(context.Context, connect.Spec, connect.ServerStream) error {
		ran = true
		return nil
	})(context.Background(), connect.Spec{Procedure: "/x/Y"}, nil)
	if !ran || err != nil {
		t.Errorf("no caller: ran=%v err=%v", ran, err)
	}
}

// TestHR655_RefusalNamesNoRecord: the refusal says what the role is for and
// carries a stable code.
// Covers: F946
func TestHR655_RefusalNamesNoRecord(t *testing.T) {
	if !strings.Contains(errInvestigatorReads.Error(), "INVESTIGATOR_READS_ONLY") {
		t.Errorf("code: %v", errInvestigatorReads)
	}
}
