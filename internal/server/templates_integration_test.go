// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/assurance"
	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/templates/templatesrpc"
	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/exposure/exposuretest"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type teamEdition struct{}

func (teamEdition) Current(context.Context) (billing.Entitlements, error) {
	return billing.Entitlements{Edition: billing.Team, Status: billing.StatusValid}, nil
}

// TestD119_EveryTemplateIsCreatedThroughTheDatabase: each of the nine
// templates, with its example parameters, is created through
// CreateFromTemplate over core's CreateDraftTx and assurance's
// SetTestCasesTx on the database: a DRAFT automation, its version and every
// baseline test stored (D96, D103 T1, D119).
func TestD119_EveryTemplateIsCreatedThroughTheDatabase(t *testing.T) {
	o := exposuretest.New(t)
	core := newAutomationsCore(o.P, nil, "")
	core.svc.Editions = teamEdition{}
	h := &templatesrpc.TemplateHandler{
		Pool: o.P, Drafts: automationDrafts{svc: core.svc},
		Tests: automationTests{svc: &assurance.Service{Pool: o.P, Ents: teamEdition{}}},
	}
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: o.Org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: o.User},
		Bindings: []td.Binding{{Role: td.RoleAutomationAuthor, Scope: td.Scope{Type: td.ScopeOrg, ID: o.Org.UUID()}}},
	}})
	list := templates.List()
	if len(list) != 9 {
		t.Fatalf("%d templates", len(list))
	}
	for _, tm := range list {
		_, cases, err := templates.Render(tm.ID, tm.Example())
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		res, err := h.CreateFromTemplate(ctx, &pantherclawv1.CreateFromTemplateRequest{
			TemplateId: tm.ID, Name: strings.ReplaceAll(tm.ID, "_", "-"), Params: tm.Example(),
		})
		if err != nil {
			t.Fatalf("%s: %v", tm.ID, err)
		}
		if int(res.GetTests()) != len(cases) || len(cases) == 0 {
			t.Fatalf("%s: %d tests stored of %d", tm.ID, res.GetTests(), len(cases))
		}
		version, err := ids.ParseUUID(res.GetVersionId())
		if err != nil {
			t.Fatal(err)
		}
		var stored int
		var state string
		if err := o.P.InTenantTx(context.Background(), o.Org, func(ctx context.Context, tx db.TenantTx) error {
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM pc.automation_test_cases WHERE version_id = $1`, version).Scan(&stored); err != nil {
				return err
			}
			return tx.QueryRow(ctx, `SELECT a.state FROM pc.automations a JOIN pc.automation_versions v ON v.automation_id = a.id
				WHERE v.id = $1`, version).Scan(&state)
		}); err != nil {
			t.Fatal(err)
		}
		if stored != len(cases) || state != "DRAFT" {
			t.Fatalf("%s: %d test cases stored, automation %s", tm.ID, stored, state)
		}
	}
}
