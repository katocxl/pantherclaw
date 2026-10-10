// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/recording"
	"github.com/katocxl/pantherclaw/internal/authority/replay"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// ReplaySource implements replay.Source. Every read runs in a READ ONLY
// tenant transaction, so the database itself refuses any write a replay
// might attempt (HR-197).
type ReplaySource struct {
	Pool        *db.Pool
	Definitions *defpg.Store
	FactStore   *factpg.Store
}

var _ replay.Source = (*ReplaySource)(nil)

func (s *ReplaySource) read(ctx context.Context, org ids.OrgID, fn func(context.Context, db.TenantTx) error) error {
	err := s.Pool.InTenantTx(ctx, org, fn, db.ReadOnly())
	if db.IsNoRows(err) || errors.Is(err, defpg.ErrNotFound) {
		return replay.ErrNotFound
	}
	return err
}

// Receipt implements replay.Source.
func (s *ReplaySource) Receipt(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (string, error) {
	var out string
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = dbq.New(tx).GetEvaluationReceipt(ctx, org, txn, int32(evaluation)) //nolint:gosec // ≤ 64
		return err
	})
	return out, err
}

// Inputs implements replay.Source.
func (s *ReplaySource) Inputs(ctx context.Context, org ids.OrgID, txn ids.UUID, evaluation int) (recording.Sealed, error) {
	var out recording.Sealed
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetEvaluationInputs(ctx, org, txn, int32(evaluation)) //nolint:gosec // ≤ 64
		if err != nil {
			return err
		}
		out = recording.Sealed{
			Format: int(row.FormatVersion), Pipeline: int(row.PipelineVersion), Inputs: row.Inputs, Truncated: row.Truncated,
		}
		copy(out.Digest[:], row.InputsSha256)
		return nil
	})
	return out, err
}

// Definition implements replay.Source.
func (s *ReplaySource) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (*defs.Definition, error) {
	var out *defs.Definition
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, _, err = s.Definitions.PinnedInTx(ctx, tx, org, pin)
		return err
	})
	return out, err
}

// Bundle implements replay.Source.
func (s *ReplaySource) Bundle(ctx context.Context, org ids.OrgID, bundle string, version int) (*pdomain.Bundle, error) {
	var out *pdomain.Bundle
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		raw, err := dbq.New(tx).GetPolicyBundleByNumber(ctx, org, bundle, int32(version)) //nolint:gosec // a stored version
		if err != nil {
			return err
		}
		out, err = storedBundle(raw)
		return err
	})
	return out, err
}

// PolicyVersion implements replay.Source.
func (s *ReplaySource) PolicyVersion(ctx context.Context, org ids.OrgID, id ids.UUID) (*pdomain.Bundle, error) {
	var out *pdomain.Bundle
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPolicyVersion(ctx, org, id)
		if err != nil {
			return err
		}
		out, err = storedBundle(row.Bundle)
		return err
	})
	return out, err
}

// Catalog implements replay.Source.
func (s *ReplaySource) Catalog(ctx context.Context, org ids.OrgID) (map[string]fdomain.Type, error) {
	var out map[string]fdomain.Type
	err := s.read(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.FactStore.CatalogInTx(ctx, tx, org)
		return err
	})
	return out, err
}

// storedBundle decodes a stored bundle as the policy store does.
func storedBundle(raw []byte) (*pdomain.Bundle, error) {
	var b pdomain.Bundle
	if err := json.Unmarshal(raw, &b, json.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("authority: stored bundle: %w", err)
	}
	if err := b.Validate(); err != nil {
		return nil, fmt.Errorf("authority: stored bundle: %w", err)
	}
	return &b, nil
}
