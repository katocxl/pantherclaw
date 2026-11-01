// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/securityevent"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/response/adapters/pgresponse"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// ReapplyControl recreates exactly a shipped control under the restore
// command's tenant transaction (G0 M13 D50). It uses the current scope
// preview and the normal path planner, so replay never claims unverified
// paths are confirmed. A missing target or conflicting control fails held.
func ReapplyControl(ctx context.Context, tx db.TenantTx, metadata securityevent.Containment, actor evdomain.Actor) error {
	c, err := (rdomain.Control{ScopeType: metadata.ScopeType, ScopeID: metadata.ScopeID, Control: metadata.Control, Operation: metadata.Operation, Reason: "re-applied after restore"}).Canonical()
	if err != nil {
		return err
	}
	q := dbq.New(tx)
	prior, err := q.GetContainmentControl(ctx, tx.OrgID(), metadata.ControlID)
	if err == nil {
		operation := ""
		if prior.Operation != nil {
			operation = *prior.Operation
		}
		if prior.ActionID != metadata.ActionID || prior.ScopeType != c.ScopeType || prior.ScopeID != c.ScopeID || prior.Control != c.Control || operation != c.Operation || prior.LiftedAt != nil {
			return errors.New("restore: conflicting or lifted containment control")
		}
		return nil
	}
	if !db.IsNoRows(err) {
		return err
	}
	if err := exists(ctx, q, tx.OrgID(), c); err != nil {
		return err
	}
	p, err := preview(ctx, tx, tx.OrgID(), c)
	if err != nil {
		return err
	}
	a := pgresponse.Action{ID: metadata.ActionID, Kind: rdomain.KindContain, ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control, Operation: c.Operation, Reason: c.Reason, Actor: actor.Type + ":" + actor.ID, Source: metadata.Source, PreviewDigest: p.Digest, PreviewSummary: summaryOf(p)}
	if metadata.Server != "" {
		a.ScopeType, a.ScopeID = rdomain.ScopeMcpServer, metadata.Server
	}
	// One action can hold many controls (a revoke's, G0 M24 D264): the first
	// one back recreates the action, and each adds its own paths.
	added, err := pgresponse.AddControlWithID(ctx, tx, tx.OrgID(), a, c, metadata.ControlID, nil)
	if err != nil {
		return err
	}
	return planPaths(ctx, tx, a.ID, rdomain.KindContain, p, added.Epoch)
}
