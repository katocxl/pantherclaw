// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/modelusage/app"
	"github.com/katocxl/pantherclaw/internal/modelusage/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type edition billing.Edition

func (e edition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Edition(e), Status: billing.StatusValid}, nil
}

func caller(roles ...td.RoleName) context.Context {
	org := ids.New[ids.Org]()
	var bs []td.Binding
	for _, r := range roles {
		bs = append(bs, td.Binding{Role: r, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}})
	}
	return tenancy.WithCaller(context.Background(), tenancy.Caller{
		Subject:    td.Subject{Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()}, Bindings: bs},
		Credential: tenancy.CredAccessToken,
	})
}

// TestHR698_TheTokenReportNeedsTeamAndBudgetRead: the monthly report is
// refused on Community and without an edition source, and to a caller
// without budget.read, before anything is read (G0 M29 D825, D829). The
// Team report itself runs in TestE2E_M29_ModelRoute.
//
// Covers: F988, HR-698
func TestHR698_TheTokenReportNeedsTeamAndBudgetRead(t *testing.T) {
	req := app.ReportRequest{Month: "2026-11", By: domain.ByTeam}
	for name, s := range map[string]*app.Service{"community": {Editions: edition(billing.Community)}, "no edition source": {}} {
		if _, err := s.Report(caller(td.RoleAuditor), req); !errors.Is(err, app.ErrTeam) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := (&app.Service{Editions: edition(billing.Team)}).Report(caller(td.RoleRunLauncher), req); err == nil || errors.Is(err, app.ErrTeam) {
		t.Errorf("without budget.read: %v", err)
	}
	if _, err := (&app.Service{Editions: edition(billing.Team)}).Report(caller(td.RoleAuditor), app.ReportRequest{Month: "2026-13", By: domain.ByTeam}); !errors.Is(err, app.ErrInvalidMonth) {
		t.Errorf("month 13: %v", err)
	}
}

// TestT318_EveryEstimateIsLabelledAndTheReportIsNotABill: the report's
// fixed statement says the numbers are provider-reported and the costs are
// estimates from the organization's prices, not a bill; the run's estimate
// carries the label "estimate".
//
// Covers: HR-698
func TestT318_EveryEstimateIsLabelledAndTheReportIsNotABill(t *testing.T) {
	if domain.EstimateLabel != "estimate" || !strings.Contains(domain.Statement, "estimates") ||
		!strings.Contains(domain.Statement, "not a bill") || !strings.Contains(domain.Statement, "your organization set") {
		t.Fatalf("label %q, statement %q", domain.EstimateLabel, domain.Statement)
	}
}
