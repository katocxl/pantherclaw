// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pghub stores Hub installs and each org's index state in PostgreSQL
// (G0 M23 D102).
package pghub

import (
	"context"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/hub/app"
	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Store implements app.Store.
type Store struct{ Pool *db.Pool }

var _ app.Store = (*Store)(nil)

func installOf(r dbq.PcHubInstall) app.Install {
	return app.Install{
		ID: r.ID, Name: r.Name, Version: r.Version, Kind: domain.Kind(r.Kind), ItemSHA256: r.ItemSha256,
		IndexVersion: uint64(r.IndexVersion), //nolint:gosec // G115: CHECK >= 1
		ResultKind:   r.ResultKind, ResultRef: r.ResultRef, InstalledBy: r.InstalledBy, InstalledAt: r.InstalledAt, Status: app.Status(r.Status),
		Claim: r.Claim, FailureReason: r.FailureReason,
	}
}

// State implements app.Store.
func (s *Store) State(ctx context.Context, org ids.OrgID) (*app.State, error) {
	var out *app.State
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetHubState(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &app.State{
			State:     domain.State{Version: uint64(r.IndexVersion), Digest: r.IndexDigest}, //nolint:gosec // G115: CHECK >= 1
			UpdatedAt: r.UpdatedAt,
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Begin implements app.Store.
func (s *Store) Begin(ctx context.Context, org ids.OrgID, c tapp.Caller, b app.Begin) (app.Install, bool, error) {
	var out app.Install
	already := false
	indexVersion := int64(b.Index.Version) //nolint:gosec // G115: Validate caps it at 2^63-1
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		st, err := q.LockHubState(ctx, org)
		var last *domain.State
		switch {
		case err == nil:
			last = &domain.State{Version: uint64(st.IndexVersion), Digest: st.IndexDigest} //nolint:gosec // G115: CHECK >= 1
		case !db.IsNoRows(err):
			return err
		}
		if err := domain.CheckAdvance(last, b.Index); err != nil {
			return err
		}
		// The statement refuses by itself what a concurrent first install
		// could still race past the lock above.
		n, err := q.AdvanceHubState(ctx, org, indexVersion, b.Index.Digest)
		if err != nil {
			return err
		}
		if n != 1 {
			return fmt.Errorf("%w: another index was accepted meanwhile", domain.ErrRollback)
		}
		cur, err := q.LockHubInstall(ctx, org, b.Entry.Name, b.Entry.Version)
		if db.IsNoRows(err) {
			r, err := q.InsertHubInstall(ctx, dbq.InsertHubInstallParams{
				OrgID: org, ID: ids.NewV7(), Name: b.Entry.Name, Version: b.Entry.Version, Kind: string(b.Entry.Kind),
				ItemSha256: b.Entry.SHA256, IndexVersion: indexVersion, InstalledBy: b.InstalledBy, Claim: ids.NewV7(),
			})
			out = installOf(r)
			return err
		}
		if err != nil {
			return err
		}
		switch {
		case cur.ItemSha256 != b.Entry.SHA256:
			return fmt.Errorf("%w: %s@%s is installed with another digest", domain.ErrDigest, b.Entry.Name, b.Entry.Version)
		case cur.Status == string(app.StatusInstalled):
			out, already = installOf(dbq.PcHubInstall{
				OrgID: cur.OrgID, ID: cur.ID, Name: cur.Name, Version: cur.Version, Kind: cur.Kind, ItemSha256: cur.ItemSha256,
				IndexVersion: cur.IndexVersion, ResultKind: cur.ResultKind, ResultRef: cur.ResultRef, InstalledBy: cur.InstalledBy,
				InstalledAt: cur.InstalledAt, Status: cur.Status,
			}), true
			return nil
		case cur.Status == string(app.StatusPending) && !cur.Stale:
			return app.ErrBusy
		}
		r, err := q.ReclaimHubInstall(ctx, dbq.ReclaimHubInstallParams{OrgID: org, ID: cur.ID, IndexVersion: indexVersion, InstalledBy: b.InstalledBy, Claim: ids.NewV7()})
		out = installOf(r)
		out.Reclaimed = true
		return err
	})
	if err != nil {
		return app.Install{}, false, err
	}
	return out, already, nil
}

// Finish implements app.Store.
func (s *Store) Finish(ctx context.Context, org ids.OrgID, c tapp.Caller, f app.Finish) (app.Install, error) {
	var out app.Install
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).FinishHubInstall(ctx, dbq.FinishHubInstallParams{
			OrgID: org, ID: f.ID, Status: string(f.Status), ResultKind: f.ResultKind, ResultRef: f.ResultRef, FailureReason: f.Reason, Claim: f.Claim,
		})
		if db.IsNoRows(err) {
			// Another worker reclaimed the row: the end of the install is its.
			return app.ErrBusy
		}
		if err != nil {
			return err
		}
		out = installOf(r)
		name, outcome := "hub.item_installed", audit.Success
		if f.Status != app.StatusInstalled {
			name, outcome = "hub.item_install_failed", audit.Failure
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: name, Actor: c.Actor(), Outcome: outcome,
			Object: &audit.Object{Type: "hub_item", ID: r.Name + "@" + r.Version},
			Details: map[string]string{
				"kind": r.Kind, "item_sha256": r.ItemSha256, "index_version": fmt.Sprint(r.IndexVersion),
				"result_kind": r.ResultKind, "result_ref": r.ResultRef, "replaced": fmt.Sprint(len(f.Replaced)),
				"failure_reason": r.FailureReason,
			},
		})
		return err
	})
	return out, err
}

// List implements app.Store.
func (s *Store) List(ctx context.Context, org ids.OrgID, limit int, before *ids.UUID) ([]app.Install, error) {
	var out []app.Install
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListHubInstalls(ctx, org, before, int32(limit)) //nolint:gosec // G115: the proto caps it
		if err != nil {
			return err
		}
		for _, r := range rows {
			out = append(out, installOf(r))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// EnvironmentID implements app.Store.
func (s *Store) EnvironmentID(ctx context.Context, org ids.OrgID, slug string) (ids.UUID, error) {
	var out ids.UUID
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).EnvironmentIDsBySlug(ctx, org, slug)
		if err != nil {
			return err
		}
		if len(rows) != 1 {
			return app.ErrNoEnvironment
		}
		out = rows[0]
		return nil
	}, db.ReadOnly())
	return out, err
}
