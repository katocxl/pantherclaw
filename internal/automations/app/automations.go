// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"
	"unicode/utf8"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// CreateAutomation creates a DRAFT automation and its execution identity
// (D8, HR-270): a service account named automation-<name>, bound to the
// automation for good, with no keys and no role bindings.
func (s *Service) CreateAutomation(ctx context.Context, name, purpose string, kind autodomain.WorkKind, owner ids.UUID) (Automation, error) {
	c, err := manager(ctx)
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
		var err error
		out, err = createAutomationTx(ctx, tx, c, name, purpose, kind, owner)
		return err
	})
	if db.IsUniqueViolation(err) {
		return Automation{}, ErrNameTaken
	}
	return out, err
}

func createAutomationTx(ctx context.Context, tx db.TenantTx, c tapp.Caller, name, purpose string, kind autodomain.WorkKind,
	owner ids.UUID,
) (Automation, error) {
	q := dbq.New(tx)
	if ok, err := q.SubjectUserActive(ctx, c.Org, owner); err != nil && !db.IsNoRows(err) {
		return Automation{}, err
	} else if !ok {
		return Automation{}, ErrOwner
	}
	id, sa := ids.NewV7(), ids.NewV7()
	aid := id
	if err := q.InsertAutomationServiceAccount(ctx, dbq.InsertAutomationServiceAccountParams{
		OrgID: c.Org, ID: sa, Name: tapp.AutomationAccountPrefix + name,
		Description: "Execution identity of automation " + name, CreatedBy: c.Principal.String(), AutomationID: &aid,
	}); err != nil {
		return Automation{}, err
	}
	if err := q.InsertAutomation(ctx, dbq.InsertAutomationParams{
		OrgID: c.Org, ID: id, Name: name, Purpose: purpose, Kind: string(kind), OwnerUserID: owner,
		ServiceAccountID: sa, CreatedBy: c.Principal.ID,
	}); err != nil {
		return Automation{}, err
	}
	r, err := q.GetAutomation(ctx, c.Org, id)
	if err != nil {
		return Automation{}, err
	}
	return automationView(r), record(ctx, tx, c.Actor(), "automation.created", id, map[string]string{
		"name": name, "kind": string(kind), "owner": owner.String(), "service_account": sa.String(),
	})
}

// Draft is a new automation with its first DRAFT version (D102, D103 T1).
type Draft struct {
	Name, Purpose string
	Kind          autodomain.WorkKind
	Owner         ids.UUID
	Definition    []byte
}

// CreateDraftTx creates, in the caller's transaction, a DRAFT automation,
// its execution identity and its first DRAFT version (D102 for D103 T1):
// CreateAutomation and CreateDraftVersion as one unit, so a later failure
// in the same transaction leaves nothing behind. The caller needs what
// both need; a taken name is ErrNameTaken and leaves the transaction
// usable.
func (s *Service) CreateDraftTx(ctx context.Context, tx db.TenantTx, in Draft) (Automation, Version, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, Version{}, err
	}
	if c.Org != tx.OrgID() {
		return Automation{}, Version{}, ErrNotFound
	}
	if err := s.edition(ctx); err != nil {
		return Automation{}, Version{}, err
	}
	if !autodomain.NamePattern.MatchString(in.Name) {
		return Automation{}, Version{}, ErrName
	}
	if n := utf8.RuneCountInString(strings.TrimSpace(in.Purpose)); n < 1 || n > 2000 || !in.Kind.Valid() {
		return Automation{}, Version{}, ErrDefinition
	}
	canonical, digest, err := parseDefinition(in.Definition)
	if err != nil {
		return Automation{}, Version{}, err
	}
	var a Automation
	var v Version
	err = tx.Savepoint(ctx, "automation_draft", func() error {
		var err error
		if a, err = createAutomationTx(ctx, tx, c, in.Name, in.Purpose, in.Kind, in.Owner); err != nil {
			return err
		}
		v, err = createVersionTx(ctx, tx, c, a.ID, canonical, digest)
		return err
	})
	if db.IsUniqueViolation(err) {
		return Automation{}, Version{}, ErrNameTaken
	}
	return a, v, err
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
			OrgID: c.Org, States: ss, AfterName: after, MaxRows: int32(min(max(limit, 1), 200)),
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

// SetOwner makes another active person the automation's owner (D68). The
// automation's pending ENABLE and ROLLOUT requests are voided: they were
// asked for under the previous owner.
func (s *Service) SetOwner(ctx context.Context, automation, owner ids.UUID) (Automation, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, err
	}
	var out Automation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.State == string(autodomain.StateRetired) {
			return ErrState
		}
		if ok, err := q.SubjectUserActive(ctx, c.Org, owner); err != nil && !db.IsNoRows(err) {
			return err
		} else if !ok {
			return ErrOwner
		}
		if a.OwnerUserID != owner {
			if err := oneRow(q.SetAutomationOwner(ctx, owner, c.Org, a.ID)); err != nil {
				return err
			}
			voided := 0
			if s.Changes != nil {
				voidedIDs, err := s.Changes.Void(ctx, tx, c, changes.DomainAutomation, a.ID, VoidOwnerChanged)
				if err != nil {
					return err
				}
				voided = len(voidedIDs)
			}
			if err := record(ctx, tx, c.Actor(), "automation.owner_changed", a.ID, map[string]string{
				"from": a.OwnerUserID.String(), "to": owner.String(), "voided_requests": itoa(voided),
			}); err != nil {
				return err
			}
		}
		r, err := q.GetAutomation(ctx, c.Org, a.ID)
		if err != nil {
			return err
		}
		out = automationView(r)
		return nil
	})
	return out, err
}
