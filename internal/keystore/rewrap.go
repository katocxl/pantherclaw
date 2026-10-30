// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Re-wrap in place (G0 M18 S18e, D157, migration 00224). Each stored key
// that is not under the current KEK is unwrapped, wrapped again, verified
// by unwrapping the new value, then written together with its new kek_id
// as pc_keystore (HR-487). Any failure before the write writes nothing and
// stops the batch (HR-486): the old value stays and still unwraps. The
// audit is a second, pc_app transaction after the write, as in the org
// deletion job (D171, D173): if it fails, the key stays re-wrapped and
// verified, and the job logs an ERROR naming it (AuditError).

// RewrapBatch bounds the keys re-wrapped per org and table in one run.
const RewrapBatch = 100

// ErrRewrapNotConfigured reports keys waiting for a re-wrap on a server
// without the pc_keystore role (database.keystore_password_file, D171).
var ErrRewrapNotConfigured = errors.New("keystore: re-wrap is not configured: set database.keystore_password_file (the pc_keystore role)")

// ErrRewrapConflict reports a key that changed between read and write; it
// is left for the next run.
var ErrRewrapConflict = errors.New("keystore: key changed during re-wrap")

// RewrapResult counts one run's re-wrapped keys and lists the stored
// kek_ids no configured provider holds.
type RewrapResult struct {
	DEKs        int
	SigningKeys int
	Unroutable  []string
}

// currentIDs lists the kek_id values that already name the current KEK: a
// file KEK is also stored without its prefix by pre-M18 rows.
func currentIDs(kp keys.KeyProvider) []string {
	cur := kp.CurrentKEK()
	if bare, ok := strings.CutPrefix(cur, keys.PrefixFile); ok {
		return []string{cur, bare}
	}
	if strings.HasPrefix(cur, keys.PrefixOpenBao) {
		return []string{cur}
	}
	return []string{cur, keys.PrefixFile + cur}
}

// RewrapOrg re-wraps up to RewrapBatch DEKs and RewrapBatch signing keys of
// org that are not under kp's current KEK. When kp is a KEKRouter, every
// stored kek_id it cannot route is audited as keys.kek_unroutable and its
// keys are skipped, so they don't stop the others; they keep failing
// closed at their first unwrap (D170). pool is pc_app's (reads and audit),
// ks pc_keystore's (the writes); without ks nothing is written and keys
// waiting for a re-wrap return ErrRewrapNotConfigured.
func RewrapOrg(ctx context.Context, pool, ks *db.Pool, kp keys.KeyProvider, org ids.OrgID) (RewrapResult, error) {
	var res RewrapResult
	cur := currentIDs(kp)
	if r, ok := kp.(KEKRouter); ok {
		unroutable, err := reportUnroutable(ctx, pool, org, r)
		if err != nil {
			return res, err
		}
		res.Unroutable = unroutable
		cur = append(cur, unroutable...)
	}
	var deks []dbq.ListDEKsToRewrapRow
	var sks []dbq.ListSigningKeysToRewrapRow
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if deks, err = q.ListDEKsToRewrap(ctx, org, cur, RewrapBatch); err != nil {
			return err
		}
		sks, err = q.ListSigningKeysToRewrap(ctx, org, cur, RewrapBatch)
		return err
	}, db.ReadOnly())
	if err != nil {
		return res, err
	}
	if ks == nil {
		if len(deks)+len(sks) > 0 {
			return res, ErrRewrapNotConfigured
		}
		return res, nil
	}
	for _, d := range deks {
		version := uint32(d.Version) //nolint:gosec // G115: versions are positive (CHECK constraint)
		if err := rewrapOne(ctx, pool, ks, kp, org, d.KekID, d.WrappedKey, dekAAD(org, d.Purpose, version), "dek",
			d.Purpose+"/"+strconv.FormatUint(uint64(version), 10),
			func(q *dbq.Queries, wrapped []byte, kek string) (int64, error) {
				return q.RewrapDEK(ctx, dbq.RewrapDEKParams{
					OrgID: org, Purpose: d.Purpose, Version: d.Version,
					OldWrappedKey: d.WrappedKey, OldKekID: d.KekID, WrappedKey: wrapped, KekID: kek,
				})
			}); err != nil {
			return res, err
		}
		res.DEKs++
	}
	for _, k := range sks {
		if err := rewrapOne(ctx, pool, ks, kp, org, k.KekID, k.WrappedPrivateKey, signingAAD(org, keys.Purpose(k.Purpose), k.Kid),
			"signing_key", k.Kid,
			func(q *dbq.Queries, wrapped []byte, kek string) (int64, error) {
				return q.RewrapSigningKey(ctx, dbq.RewrapSigningKeyParams{
					OrgID: org, Kid: k.Kid,
					OldWrappedPrivateKey: k.WrappedPrivateKey, OldKekID: k.KekID, WrappedPrivateKey: wrapped, KekID: kek,
				})
			}); err != nil {
			return res, err
		}
		res.SigningKeys++
	}
	return res, nil
}

// rewrapOne verifies before it writes (HR-487). The write, as pc_keystore
// (the only role with the two columns, D171), is a compare-and-swap on
// both old columns, and the 00224 trigger refuses a change of one column
// without the other. The audit is a separate pc_app transaction after the
// write (pc_keystore cannot write the ledger), not atomic with it: a failed
// audit returns an AuditError naming the key, which stays re-wrapped.
func rewrapOne(ctx context.Context, pool, ks *db.Pool, kp keys.KeyProvider, org ids.OrgID, oldKEK string, oldWrapped, aad []byte,
	objType, objID string, write func(*dbq.Queries, []byte, string) (int64, error),
) error {
	if inner, err := keys.KEKOf(oldWrapped); err != nil || !keys.SameKEK(oldKEK, inner) {
		return fmt.Errorf("keystore: re-wrap %s %s: %w", objType, objID, keys.ErrUnwrap)
	}
	wrapped, kek, err := keys.Rewrap(ctx, kp, oldWrapped, aad)
	if err != nil {
		return fmt.Errorf("keystore: re-wrap %s %s: %w", objType, objID, err)
	}
	if keys.SameKEK(kek, oldKEK) || bytes.Equal(wrapped, oldWrapped) {
		return fmt.Errorf("keystore: re-wrap %s %s: %w", objType, objID, keys.ErrRewrapVerify)
	}
	err = ks.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		n, err := write(dbq.New(tx), wrapped, kek)
		if err != nil {
			return fmt.Errorf("keystore: re-wrap %s %s: %w", objType, objID, err)
		}
		if n != 1 {
			return fmt.Errorf("keystore: re-wrap %s %s: %w", objType, objID, ErrRewrapConflict)
		}
		return nil
	})
	if err != nil {
		return err
	}
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, err := audit.Record(ctx, tx, audit.Event{
			Name: objType + ".rewrapped", Actor: Actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: objType, ID: objID},
			Details: map[string]string{"from_kek_id": oldKEK, "kek_id": kek},
		})
		return err
	})
	if err != nil {
		return &AuditError{Object: objType + " " + objID, KEKID: kek, Err: err}
	}
	return nil
}

// AuditError reports a key that was re-wrapped and written, but whose
// audit entry could not be recorded (D173).
type AuditError struct {
	Object string // "dek purpose/version" or "signing_key kid"
	KEKID  string
	Err    error
}

func (e *AuditError) Error() string {
	return "keystore: " + e.Object + " re-wrapped to " + e.KEKID + " but not audited: " + e.Err.Error()
}

func (e *AuditError) Unwrap() error { return e.Err }

// reportUnroutable audits each stored kek_id of org that r cannot route.
func reportUnroutable(ctx context.Context, pool *db.Pool, org ids.OrgID, r KEKRouter) ([]string, error) {
	var out []string
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		stored, err := dbq.New(tx).ListStoredKEKIDs(ctx, org)
		if err != nil {
			return err
		}
		for _, id := range stored {
			if r.Routes(id) {
				continue
			}
			out = append(out, id)
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "keys.kek_unroutable", Actor: Actor, Outcome: audit.Failure,
				Object:  &audit.Object{Type: "kek", ID: id},
				Details: map[string]string{"kek_id": id},
			}); err != nil {
				return err
			}
		}
		return nil
	})
	return out, err
}
