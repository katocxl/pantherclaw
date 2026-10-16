// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"
	"unicode/utf8"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// CreateAutomation creates a DRAFT automation and its execution identity
// (D8, HR-270): a service account named automation-<name>, bound to the
// automation for good, with no keys and no role bindings.
func (s *Service) CreateAutomation(ctx context.Context, name, purpose string, kind autodomain.WorkKind, owner ids.UUID) (Automation, error) {
	c, err := person(ctx, td.PermAutomationManage)
	if err != nil {
		return Automation{}, err
	}
	if err := s.edition(ctx); err != nil {
		return Automation{}, err
	}
	if !autodomain.NamePattern.MatchString(name) {
		return Automation{}, ErrName
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(purpose)); n < 1 || n > 2000 || !kind.Valid() {
		return Automation{}, ErrDefinition
	}
	var out Automation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if ok, err := q.SubjectUserActive(ctx, c.Org, owner); err != nil && !db.IsNoRows(err) {
			return err
		} else if !ok {
			return ErrOwner
		}
		id, sa := ids.NewV7(), ids.NewV7()
		aid := id
		if err := q.InsertAutomationServiceAccount(ctx, dbq.InsertAutomationServiceAccountParams{
			OrgID: c.Org, ID: sa, Name: tapp.AutomationAccountPrefix + name,
			Description: "Execution identity of automation " + name, CreatedBy: c.Principal.String(), AutomationID: &aid,
		}); err != nil {
			return err
		}
		if err := q.InsertAutomation(ctx, dbq.InsertAutomationParams{
			OrgID: c.Org, ID: id, Name: name, Purpose: purpose, Kind: string(kind), OwnerUserID: owner,
			ServiceAccountID: sa, CreatedBy: c.Principal.ID,
		}); err != nil {
			return err
		}
		r, err := q.GetAutomation(ctx, c.Org, id)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.created", id, map[string]string{
			"name": name, "kind": string(kind), "owner": owner.String(), "service_account": sa.String(),
		})
	})
	if db.IsUniqueViolation(err) {
		return Automation{}, ErrNameTaken
	}
	return out, err
}

// GetAutomation returns an automation with its ACTIVE ceiling.
func (s *Service) GetAutomation(ctx context.Context, id ids.UUID) (Automation, error) {
	c, err := reader(ctx)
	if err != nil {
		return Automation{}, err
	}
	var out Automation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := loadAutomation(ctx, q, c.Org, id, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return attachCeiling(ctx, q, c.Org, &out)
	}, db.ReadOnly())
	return out, err
}

func attachCeiling(ctx context.Context, q *dbq.Queries, org ids.OrgID, a *Automation) error {
	r, err := q.GetActiveAutomationCeiling(ctx, org, a.ID)
	switch {
	case db.IsNoRows(err):
		return nil
	case err != nil:
		return err
	}
	a.Ceiling = ceilingView(r)
	return nil
}

// ListAutomations lists automations by name after `after` (paging).
func (s *Service) ListAutomations(ctx context.Context, states []autodomain.State, after string, limit int) ([]Automation, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	ss := make([]string, 0, len(states))
	for _, x := range states {
		ss = append(ss, string(x))
	}
	var out []Automation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListAutomations(ctx, dbq.ListAutomationsParams{
			OrgID: c.Org, States: ss, AfterName: after, MaxRows: int32(min(max(limit, 1), 200)), //nolint:gosec // bounded
		})
		if err != nil {
			return err
		}
		for _, r := range rows {
			a := automationView(r)
			if err := attachCeiling(ctx, q, c.Org, &a); err != nil {
				return err
			}
			out = append(out, a)
		}
		return nil
	}, db.ReadOnly())
	return out, err
}
