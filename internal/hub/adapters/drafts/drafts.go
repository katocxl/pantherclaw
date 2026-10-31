// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package drafts connects the Hub install routes to each kind's own use case
// (G0 M23 D104). Every adapter calls the use case an API caller would, so its
// permission and edition checks apply unchanged, and none activates, publishes
// or enables anything (HR-561). FindDraft is what a reclaimed install uses to
// recognise the draft a crash left behind (D130); it only reads.
package drafts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"

	autoapp "github.com/katocxl/pantherclaw/internal/automations/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defsapp "github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	reflexapp "github.com/katocxl/pantherclaw/internal/reflex/app"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

var errNoDraft = errors.New("hub: no such draft")

// find runs one read in the caller's org. A row that is not there is no
// draft, not an error.
func find(ctx context.Context, pool *db.Pool, read func(context.Context, *dbq.Queries, ids.OrgID) (ids.UUID, error)) (string, bool, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return "", false, err
	}
	var id ids.UUID
	err = pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		id, err = read(ctx, dbq.New(tx), c.Org)
		return err
	}, db.ReadOnly())
	if db.IsNoRows(err) || errors.Is(err, errNoDraft) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return id.String(), true, nil
}

// Policies stores a DRAFT policy version through the policy use case.
type Policies struct {
	*policyapp.Versions
	Pool *db.Pool
}

// canonical is a bundle without its version, the one field a store sets.
func canonical(raw []byte) ([]byte, error) {
	var b pdomain.Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	b.Version = 0
	return json.Marshal(b, json.Deterministic(true))
}

// FindDraft implements app.PolicyDrafts.
func (p Policies) FindDraft(ctx context.Context, raw []byte) (string, bool, error) {
	want, err := canonical(raw)
	if err != nil {
		return "", false, err
	}
	return find(ctx, p.Pool, func(ctx context.Context, q *dbq.Queries, org ids.OrgID) (ids.UUID, error) {
		rows, err := q.ListHubPolicyDrafts(ctx, org)
		if err != nil {
			return ids.UUID{}, err
		}
		for _, r := range rows {
			if have, err := canonical(r.Bundle); err == nil && bytes.Equal(have, want) {
				return r.ID, nil
			}
		}
		return ids.UUID{}, errNoDraft
	})
}

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

// FindDraft implements app.DetectionDrafts.
func (d Detections) FindDraft(ctx context.Context, content string) (string, bool, error) {
	sum := sha256.Sum256([]byte(content))
	return find(ctx, d.Rules.Pool, func(ctx context.Context, q *dbq.Queries, org ids.OrgID) (ids.UUID, error) {
		return q.FindHubCustomRule(ctx, org, sum[:])
	})
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

// FindDraft implements app.AutomationDrafts.
func (a Automations) FindDraft(ctx context.Context, b domain.AutomationBody) (string, bool, error) {
	d, err := autodomain.Parse([]byte(b.Definition))
	if err != nil {
		// Not this method's refusal: CreateDraft gives the clear one.
		return "", false, nil //nolint:nilerr // the draft is made next, and refused there
	}
	digest, err := d.Digest()
	if err != nil {
		return "", false, err
	}
	return find(ctx, a.Pool, func(ctx context.Context, q *dbq.Queries, org ids.OrgID) (ids.UUID, error) {
		return q.FindHubAutomation(ctx, org, b.AutomationName, digest)
	})
}

// Packages installs a tool package through ImportPackage's use case.
type Packages struct{ Admin *defsapp.Admin }

// ImportPackage implements app.PackageImports.
func (p Packages) ImportPackage(ctx context.Context, name, version, targets string, raw []byte) error {
	_, _, err := p.Admin.Import(ctx, name, version, targets, raw)
	return err
}
