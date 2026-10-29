// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/investigations"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// inspectProcedures is the run inspector (rows26 D20; HR-401): it needs
// evidence.read on the run, and each section its own permission, which
// the use case checks where the run's agent lives.
var inspectProcedures = map[string]td.Permission{
	pantherclawv1connect.InvestigationServiceInspectRunProcedure: td.PermEvidenceRead,
}

func init() { maps.Copy(procedurePermissions, inspectProcedures) }

// inspectBudgets reads the remaining limits of an inspection's budget
// lines from the grants' budget state (F227).
type inspectBudgets struct {
	state func(context.Context, domain.GrantID) ([]grantsapp.AccountState, error) // grantsapp.Service.BudgetState
}

var _ investigations.BudgetLimits = inspectBudgets{}

func (b inspectBudgets) Remaining(ctx context.Context, grants []ids.UUID) (map[ids.UUID]string, error) {
	out := map[ids.UUID]string{}
	for _, g := range grants {
		id, err := domain.ParseGrantID(g.String())
		if err != nil {
			continue
		}
		// A grant the caller may not read the budget of, or one that is gone,
		// leaves its lines without remaining; the inspection does not fail
		// (HR-401, rows26 D25).
		accounts, err := b.state(ctx, id)
		if c := pcerr.CodeOf(err); c == pcerr.PermissionDenied || c == pcerr.NotFound {
			continue
		} else if err != nil {
			return nil, err
		}
		for _, a := range accounts {
			if left := a.Available(); left != nil {
				out[a.ID] = left.String()
			}
		}
	}
	return out, nil
}
