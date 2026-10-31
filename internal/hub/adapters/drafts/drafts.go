// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package drafts connects the Hub install routes to each kind's own use case
// (G0 M23 D104). Every adapter calls the use case an API caller would, so its
// permission and edition checks apply unchanged, and none activates, publishes
// or enables anything (HR-561).
package drafts

import (
	"context"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Detections installs a detection rule through CreateCustomRule.
type Detections struct{ Rules *reflexapp.Detections }

// CreateDraft implements app.DetectionDrafts.
func (d Detections) CreateDraft(ctx context.Context, content string) (string, error) {
	r, err := d.Rules.CreateCustomRule(ctx, content)
	if err != nil {
		return "", err
	}
	return r.Custom.ID.String(), nil
}

// Automations installs an automation through CreateDraftTx: the automation
// and its first version in one transaction, owned by the caller.
type Automations struct {
	Pool *db.Pool
	Svc  *autoapp.Service
}

// CreateDraft implements app.AutomationDrafts.
func (a Automations) CreateDraft(ctx context.Context, b domain.AutomationBody) (string, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return "", err
	}
	var id string
	err = a.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		out, _, err := a.Svc.CreateDraftTx(ctx, tx, autoapp.Draft{
			Name: b.AutomationName, Purpose: b.Purpose, Kind: autodomain.WorkKind(b.WorkKind), Owner: c.Principal.ID, Definition: []byte(b.Definition),
		})
		id = out.ID.String()
		return err
	})
	return id, err
}

// Packages installs a tool package through ImportPackage's use case.
type Packages struct{ Admin *defsapp.Admin }

// ImportPackage implements app.PackageImports.
func (p Packages) ImportPackage(ctx context.Context, name, version, targets string, raw []byte) error {
	_, _, err := p.Admin.Import(ctx, name, version, targets, raw)
	return err
}
