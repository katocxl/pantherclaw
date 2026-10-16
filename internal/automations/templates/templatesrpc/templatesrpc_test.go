// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package templatesrpc_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/templates"
	"github.com/katocxl/pantherclaw/internal/automations/templates/templatesrpc"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

type drafts struct{ calls int }

func (d *drafts) CreateDraftTx(context.Context, db.TenantTx, templatesrpc.Draft) (ids.UUID, ids.UUID, error) {
	d.calls++
	return ids.NewV7(), ids.NewV7(), nil
}

type tests struct{ calls int }

func (s *tests) SetTestCasesTx(context.Context, db.TenantTx, ids.UUID, []templates.TestCase) (int, error) {
	s.calls++
	return 0, nil
}

// TestD103_CreateFromTemplateNeverCreatesPartially: the automation, its
// version and its baseline tests are created in one transaction, so
// without the draft port, the test store or the pool nothing is created
// and the call answers UNAVAILABLE (D103 T1).
func TestD103_CreateFromTemplateNeverCreatesPartially(t *testing.T) {
	org := ids.New[ids.Org]()
	ctx := tenancy.WithCaller(context.Background(), tenancy.Caller{Subject: td.Subject{
		Org: org, Principal: td.PrincipalRef{Kind: td.KindUser, ID: ids.NewV7()},
		Bindings: []td.Binding{{Role: td.RoleAutomationAuthor, Scope: td.Scope{Type: td.ScopeOrg, ID: org.UUID()}}},
	}})
	req := &pantherclawv1.CreateFromTemplateRequest{TemplateId: "grant_lifecycle", Name: "lifecycle"}
	for name, h := range map[string]func(*drafts, *tests) *templatesrpc.TemplateHandler{
		"no test store": func(d *drafts, _ *tests) *templatesrpc.TemplateHandler {
			return &templatesrpc.TemplateHandler{Pool: &db.Pool{}, Drafts: d}
		},
		"no drafts": func(_ *drafts, s *tests) *templatesrpc.TemplateHandler {
			return &templatesrpc.TemplateHandler{Pool: &db.Pool{}, Tests: s}
		},
		"no pool": func(d *drafts, s *tests) *templatesrpc.TemplateHandler {
			return &templatesrpc.TemplateHandler{Drafts: d, Tests: s}
		},
	} {
		d, s := &drafts{}, &tests{}
		if _, err := h(d, s).CreateFromTemplate(ctx, req); !errors.Is(err, templatesrpc.ErrUnavailable) || d.calls+s.calls != 0 {
			t.Errorf("%s: %v, %d draft and %d test calls", name, err, d.calls, s.calls)
		}
	}
}
