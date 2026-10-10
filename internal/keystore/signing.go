// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package keystore persists PantherClaw's keys in PostgreSQL (SB-3,
// ADR-0012): platform signing keys under the reserved platform org, and
// per-org data encryption keys. Private material is stored only wrapped by
// a KEK from keys.KeyProvider; the wrap AAD binds org, purpose and key
// identity, so wrapped keys cannot be moved between rows (HR-062).
// Creation, rotation and revocation are recorded as platform-audit events
// in the same transaction (SB-4, fail closed).
package keystore

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"slices"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Actor is recorded on keystore audit events.
var Actor = domain.Actor{Type: "system", ID: "keystore"}

func signingAAD(org ids.OrgID, purpose keys.Purpose, kid string) []byte {
	return []byte("pc-signing-key-v1|" + org.String() + "|" + string(purpose) + "|" + kid)
}

// LoadSigningKeys loads every non-revoked platform signing key into reg,
// creating an active key for each Ed25519 purpose, the anchors purpose and
// each of extra that has none. The checkpoints_pq key is created only when
// the caller names it in extra (evidence.mldsa_cosign). Unwrapping fails
// closed: a key that cannot be unwrapped stops the load.
func LoadSigningKeys(ctx context.Context, pool *db.Pool, kp keys.KeyProvider, reg *keys.Registry, extra ...keys.Purpose) error {
	org := ids.PlatformOrg
	want := append(keys.Purposes(), keys.PurposeAnchors)
	for _, p := range extra {
		if !p.Valid() {
			return fmt.Errorf("keystore: unknown purpose %q", p)
		}
		if !slices.Contains(want, p) {
			want = append(want, p)
		}
	}
	return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		active := map[keys.Purpose]bool{}
		for _, r := range rows {
			if keys.Purpose(r.Purpose).Algorithm() != keys.AlgEdDSA {
				if err := loadAltKey(ctx, kp, reg, org, r); err != nil {
					return err
				}
				active[keys.Purpose(r.Purpose)] = active[keys.Purpose(r.Purpose)] || r.State == string(keys.StateActive)
				continue
			}
			k := keys.SigningKey{KID: r.Kid, Purpose: keys.Purpose(r.Purpose), State: keys.State(r.State), Public: ed25519.PublicKey(r.PublicKey)}
			// The gateway CA's retiring keys keep their private half, so that
			// their (deterministic) CA certificates stay trusted during a
			// rotation (G0 M6); only the active key ever issues.
			if k.State == keys.StateActive || (k.State == keys.StateRetiring && k.Purpose == keys.PurposeGatewayCA) {
				seed, err := kp.Unwrap(ctx, r.WrappedPrivateKey, signingAAD(org, k.Purpose, k.KID))
				if err != nil {
					return fmt.Errorf("keystore: unwrap signing key %s: %w", k.KID, err)
				}
				if len(seed) != ed25519.SeedSize {
					return fmt.Errorf("keystore: signing key %s has a malformed seed", k.KID)
				}
				k.Private = pclog.NewSecret(ed25519.NewKeyFromSeed(seed))
				if k.State == keys.StateActive {
					active[k.Purpose] = true
				}
			}
			if err := reg.Put(k); err != nil {
				return fmt.Errorf("keystore: %w", err)
			}
		}
		for _, p := range want {
			if active[p] {
				continue
			}
			if _, err := createSigningKey(ctx, tx, kp, reg, p); err != nil {
				return err
			}
		}
		return nil
	})
}

// loadAltKey loads an ES256 or ML-DSA-65 key; only the active one is
// unwrapped.
func loadAltKey(ctx context.Context, kp keys.KeyProvider, reg *keys.Registry, org ids.OrgID, r dbq.ListSigningKeysRow) error {
	p := keys.Purpose(r.Purpose)
	if keys.Algorithm(r.Algorithm) != p.Algorithm() {
		return fmt.Errorf("keystore: signing key %s has algorithm %s, not %s", r.Kid, r.Algorithm, p.Algorithm())
	}
	k := keys.AltKey{KID: r.Kid, Purpose: p, State: keys.State(r.State), Public: r.PublicKey}
	if k.State == keys.StateActive {
		private, err := kp.Unwrap(ctx, r.WrappedPrivateKey, signingAAD(org, p, r.Kid))
		if err != nil {
			return fmt.Errorf("keystore: unwrap signing key %s: %w", r.Kid, err)
		}
		if k, err = keys.OpenAltKey(p, r.Kid, r.PublicKey, private); err != nil {
			return fmt.Errorf("keystore: %w", err)
		}
	}
	if err := reg.PutAlt(k); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	return nil
}

// createSigningKey creates, stores and audits a new active key of p, puts
// it in reg when reg is not nil, and returns its kid.
func createSigningKey(ctx context.Context, tx db.TenantTx, kp keys.KeyProvider, reg *keys.Registry, p keys.Purpose) (string, error) {
	var kid string
	var public, private []byte
	var put func() error
	if p.Algorithm() == keys.AlgEdDSA {
		k, err := keys.GenerateSigningKey(p)
		if err != nil {
			return "", err
		}
		kid, public, private = k.KID, k.Public, k.Private.Reveal().Seed()
		put = func() error { return reg.Put(k) }
	} else {
		k, priv, err := keys.GenerateAltKey(p)
		if err != nil {
			return "", err
		}
		kid, public, private = k.KID, k.Public, priv.Reveal()
		put = func() error { return reg.PutAlt(k) }
	}
	wrapped, err := kp.Wrap(ctx, private, signingAAD(tx.OrgID(), p, kid))
	if err != nil {
		return "", fmt.Errorf("keystore: wrap: %w", err)
	}
	if err := dbq.New(tx).InsertSigningKey(ctx, dbq.InsertSigningKeyParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), Kid: kid, Purpose: string(p), Algorithm: string(p.Algorithm()),
		PublicKey: public, WrappedPrivateKey: wrapped, KekID: kp.CurrentKEK(),
	}); err != nil {
		return "", fmt.Errorf("keystore: insert signing key: %w", err)
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "signing_key.created", Actor: Actor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "signing_key", ID: kid},
		Details: map[string]string{"purpose": string(p), "algorithm": string(p.Algorithm()), "kek_id": kp.CurrentKEK()},
	}); err != nil {
		return "", err
	}
	if reg != nil {
		if err := put(); err != nil {
			return "", fmt.Errorf("keystore: %w", err)
		}
	}
	return kid, nil
}

// ErrNotFound reports a missing key.
var ErrNotFound = errors.New("keystore: key not found")

// RotateSigningKey moves the active key of purpose to RETIRING (it keeps
// verifying during the overlap) and creates a new active key. Reload the
// registry afterwards.
func RotateSigningKey(ctx context.Context, pool *db.Pool, kp keys.KeyProvider, p keys.Purpose, actor domain.Actor) (newKID string, err error) {
	if !p.Valid() {
		return "", fmt.Errorf("keystore: unknown purpose %q", p)
	}
	org := ids.PlatformOrg
	err = pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Purpose == string(p) && r.State == string(keys.StateActive) {
				if err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
					OrgID: org, Kid: r.Kid, FromState: string(keys.StateActive), ToState: string(keys.StateRetiring),
				})); err != nil {
					return err
				}
				if _, err := audit.Record(ctx, tx, audit.Event{
					Name: "signing_key.retiring", Actor: actor, Outcome: audit.Success,
					Object: &audit.Object{Type: "signing_key", ID: r.Kid}, Details: map[string]string{"purpose": r.Purpose},
				}); err != nil {
					return err
				}
			}
		}
		kid, err := createSigningKey(ctx, tx, kp, nil, p)
		if err != nil {
			return err
		}
		newKID = kid
		return nil
	})
	return newKID, err
}

// ReplaceSigningKey gives purpose a new active key and revokes every
// earlier key of it in the same transaction, with no overlap: nothing the
// old keys signed is trusted any longer. It is for keys whose holders must
// be set up again anyway, such as the internal gateway CA, whose gateways
// re-enroll with the new pin (founder decision 2026-10-10). It returns the
// new key id and the revoked ones. Reload the registry afterwards.
func ReplaceSigningKey(ctx context.Context, pool *db.Pool, kp keys.KeyProvider, p keys.Purpose, actor domain.Actor) (string, []string, error) {
	if !p.Valid() {
		return "", nil, fmt.Errorf("keystore: unknown purpose %q", p)
	}
	org := ids.PlatformOrg
	var newKID string
	var revoked []string
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		newKID, revoked = "", nil
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.Purpose != string(p) || (r.State != string(keys.StateActive) && r.State != string(keys.StateRetiring)) {
				continue
			}
			if r.State == string(keys.StateActive) {
				if err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
					OrgID: org, Kid: r.Kid, FromState: string(keys.StateActive), ToState: string(keys.StateRetiring),
				})); err != nil {
					return err
				}
			}
			if err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
				OrgID: org, Kid: r.Kid, FromState: string(keys.StateRetiring), ToState: string(keys.StateRevoked),
			})); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "signing_key.revoked", Actor: actor, Outcome: audit.Success,
				Object: &audit.Object{Type: "signing_key", ID: r.Kid}, Details: map[string]string{"purpose": r.Purpose, "reason": "replaced"},
			}); err != nil {
				return err
			}
			revoked = append(revoked, r.Kid)
		}
		kid, err := createSigningKey(ctx, tx, kp, nil, p)
		if err != nil {
			return err
		}
		newKID = kid
		return nil
	})
	if err != nil {
		return "", nil, err
	}
	return newKID, revoked, nil
}

// RevokeSigningKey revokes a retiring key (an active key must be rotated
// first, so a purpose is never left without a signer by accident).
func RevokeSigningKey(ctx context.Context, pool *db.Pool, kid string, actor domain.Actor) error {
	org := ids.PlatformOrg
	return pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
			OrgID: org, Kid: kid, FromState: string(keys.StateRetiring), ToState: string(keys.StateRevoked),
		}))
		if errors.Is(err, db.ErrLostRace) {
			return fmt.Errorf("%w: no retiring key %q", ErrNotFound, kid)
		}
		if err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "signing_key.revoked", Actor: actor, Outcome: audit.Success,
			Object: &audit.Object{Type: "signing_key", ID: kid},
		})
		return err
	})
}
