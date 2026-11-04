// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgstore

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"

	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Org package-signing keys (HR-162, ADR-0020): the definitions/app Keys
// port. Registrations, revocations and imports of one org take the same
// advisory lock, so the active-key limit and the one-signer-per-operation
// rule cannot be raced.

var _ app.Keys = (*Store)(nil)

func keyOf(r dbq.PcPackageSigningKey) app.SigningKey {
	k := app.SigningKey{
		ID: r.ID, KID: r.Kid, Name: r.Name, Public: ed25519.PublicKey(r.PublicKey), State: app.KeyState(r.State),
		CreatedBy: r.CreatedBy, CreatedAt: r.CreatedAt,
	}
	if r.RevokeReason != nil {
		k.Reason = app.RevokeReason(*r.RevokeReason)
	}
	if r.RevokedBy != nil {
		k.RevokedBy = *r.RevokedBy
	}
	if r.RevokedAt != nil {
		k.RevokedAt = *r.RevokedAt
	}
	if r.MetadataVersion.Valid && r.MetadataDigest != nil {
		k.Metadata = &trust.State{Version: r.MetadataVersion.Int64, PayloadDigest: *r.MetadataDigest}
	}
	return k
}

// SigningKey implements app.Keys.
func (s *Store) SigningKey(ctx context.Context, org ids.OrgID, kid string) (app.SigningKey, error) {
	var out app.SigningKey
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetPackageSigningKey(ctx, org, kid)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		out = keyOf(r)
		return err
	}, db.ReadOnly())
	return out, err
}

// ListSigningKeys implements app.Keys.
func (s *Store) ListSigningKeys(ctx context.Context, org ids.OrgID) ([]app.SigningKey, error) {
	var out []app.SigningKey
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListPackageSigningKeys(ctx, org)
		for _, r := range rows {
			out = append(out, keyOf(r))
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// RegisterSigningKey implements app.Keys.
func (s *Store) RegisterSigningKey(ctx context.Context, org ids.OrgID, k app.SigningKey, ev *audit.Event) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockPackageImports(ctx, org.String()); err != nil {
			return err
		}
		n, err := q.CountPackageSigningKeys(ctx, k.KID, org)
		switch {
		case err != nil:
			return err
		case n.SameKid > 0:
			return app.ErrKeyRegistered
		case n.Active >= app.MaxActiveSigningKeys:
			return app.ErrKeyLimit
		}
		if err := q.InsertPackageSigningKey(ctx, dbq.InsertPackageSigningKeyParams{
			OrgID: org, ID: k.ID, Kid: k.KID, PublicKey: k.Public, Name: k.Name, CreatedBy: k.CreatedBy,
		}); err != nil {
			if db.IsUniqueViolation(err) {
				return app.ErrKeyRegistered
			}
			return err
		}
		return record(ctx, tx, ev)
	})
}

// RevokeSigningKey implements app.Keys. A compromised key's transaction
// raises the containment epoch first (G0 M4 part 2, design decision 8),
// then takes the import lock, so an import racing it either finishes first
// (and its version is withdrawn here) or finds the key revoked.
func (s *Store) RevokeSigningKey(ctx context.Context, org ids.OrgID, kid string, reason app.RevokeReason, by string, ev *audit.Event) ([]app.VersionChange, error) {
	var moved []app.VersionChange
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		moved = nil
		q := dbq.New(tx)
		if reason == app.RevokeCompromised {
			if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
				return fmt.Errorf("definitions: containment epoch: %w", err)
			}
		}
		if err := q.LockPackageImports(ctx, org.String()); err != nil {
			return err
		}
		reasonText := string(reason)
		keyID, err := q.RevokePackageSigningKey(ctx, dbq.RevokePackageSigningKeyParams{
			Reason: &reasonText, RevokedBy: &by, OrgID: org, Kid: kid,
		})
		if db.IsNoRows(err) {
			return app.ErrConflict
		}
		if err != nil {
			return err
		}
		if err := record(ctx, tx, ev); err != nil {
			return err
		}
		if reason != app.RevokeCompromised {
			return nil
		}
		versions, err := q.ListVersionsSignedBy(ctx, org, &keyID)
		if err != nil {
			return err
		}
		for _, v := range versions {
			from := domain.State(v.State)
			to, ok := app.Withdrawn(from)
			if !ok {
				continue
			}
			if err := db.ExpectOneRow(q.TransitionPackageVersion(ctx, dbq.TransitionPackageVersionParams{
				ToState: string(to), OrgID: org, ID: v.ID, FromState: string(from),
			})); err != nil {
				return err
			}
			if ev != nil {
				if err := record(ctx, tx, &audit.Event{
					Name: auditkind.PackageTransitioned, Actor: ev.Actor, Outcome: audit.Success,
					Object:  &audit.Object{Type: "package_version", ID: trust.Key(v.Name, v.Version)},
					Details: map[string]string{"from": string(from), "to": string(to), "reason": "signing_key_compromised", "signing_key": kid},
				}); err != nil {
					return err
				}
			}
			moved = append(moved, app.VersionChange{Name: v.Name, Version: v.Version, From: from, To: to})
		}
		return nil
	})
	if errors.Is(err, db.ErrLostRace) {
		return nil, app.ErrConflict
	}
	return moved, err
}

// VersionSigner implements app.Keys.
func (s *Store) VersionSigner(ctx context.Context, org ids.OrgID, pkg, version string) (*app.SigningKey, error) {
	var out *app.SigningKey
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		id, err := q.GetVersionSigningKey(ctx, org, pkg, version)
		switch {
		case db.IsNoRows(err):
			return ErrNotFound
		case err != nil || id == nil:
			return err
		}
		r, err := q.GetPackageSigningKeyByID(ctx, org, *id)
		if err != nil {
			return err
		}
		k := keyOf(r)
		out = &k
		return nil
	}, db.ReadOnly())
	return out, err
}

// advanceKeyTrust records the metadata accepted under an org key, only
// while the key is active and unchanged since the import read it.
func advanceKeyTrust(ctx context.Context, q *dbq.Queries, org ids.OrgID, rec app.Record) error {
	p := dbq.AdvancePackageKeyTrustParams{
		Version: pgtype.Int8{Int64: rec.Metadata.Version, Valid: true}, PayloadDigest: &rec.Metadata.PayloadDigest,
		ExpiresAt: &rec.MetadataExpiry, OrgID: org, ID: *rec.SigningKey,
	}
	if prev := rec.PreviousMetadata; prev != nil {
		p.PrevVersion, p.PrevDigest = pgtype.Int8{Int64: prev.Version, Valid: true}, &prev.PayloadDigest
	}
	return db.ExpectOneRow(q.AdvancePackageKeyTrust(ctx, p))
}

// checkOperations refuses a package defining an operation that a
// non-retired version from the other kind of signer defines (HR-162).
func checkOperations(ctx context.Context, q *dbq.Queries, org ids.OrgID, rec app.Record) error {
	ops := make([]string, 0, len(rec.Package.Definitions))
	for _, d := range rec.Package.Definitions {
		ops = append(ops, d.Operation)
	}
	taken, err := q.OperationsTakenByOtherSigner(ctx, org, ops, rec.SigningKey != nil)
	if err != nil {
		return err
	}
	if len(taken) > 0 {
		return fmt.Errorf("%w: %s", app.ErrOperationTaken, taken[0])
	}
	return nil
}
