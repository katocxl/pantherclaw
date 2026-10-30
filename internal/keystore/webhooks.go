// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"crypto/ed25519"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Webhook key lifecycle (G0 M20 D251, D261).
const (
	// WebhookKeyOverlap is how long a rotated webhooks key stays in the
	// org's JWKS, so receivers keep verifying what it signed (HR-512).
	WebhookKeyOverlap = 24 * time.Hour
	// webhookKeyCache is how long a process signs with an unwrapped key
	// before reading the org's ACTIVE key again. A key rotated elsewhere
	// keeps verifying for the overlap, far longer than this.
	webhookKeyCache = time.Minute
)

// Webhook key errors.
var (
	// ErrWebhookKeyRotating refuses a rotation while a RETIRING key is still
	// in its overlap: at most one ACTIVE and one RETIRING key (D261).
	ErrWebhookKeyRotating = errors.New("keystore: the previous webhook key is still retiring")
	// ErrNoWebhookKey reports an org without an ACTIVE webhooks key.
	ErrNoWebhookKey     = errors.New("keystore: the org has no webhook key")
	errPlatformWebhooks = errors.New("keystore: the platform org has no webhook key")
)

// WebhookKey is the public view of one of an org's webhooks keys.
type WebhookKey struct {
	KID       string
	State     keys.State
	Public    ed25519.PublicKey
	CreatedAt time.Time
	// RetiresAt is when a RETIRING key leaves the JWKS (zero for ACTIVE).
	RetiresAt time.Time
}

// WebhookKeys keeps each organization's Ed25519 `webhooks` key in pc.keys
// under that org (RLS), wrapped with an AAD that binds the org, so a key
// signs only its own org's webhooks and a row moved to another org does
// not unwrap (HR-062, HR-511). It implements the notifications signer.
type WebhookKeys struct {
	pool *db.Pool
	kp   keys.KeyProvider
	now  func() time.Time

	mu    sync.Mutex
	cache map[ids.OrgID]cachedWebhookKey
}

type cachedWebhookKey struct {
	kid  string
	priv ed25519.PrivateKey
	at   time.Time
}

// NewWebhookKeys returns the per-org webhook key store.
func NewWebhookKeys(pool *db.Pool, kp keys.KeyProvider) *WebhookKeys {
	return &WebhookKeys{pool: pool, kp: kp, now: time.Now, cache: map[ids.OrgID]cachedWebhookKey{}}
}

func tenantOrg(org ids.OrgID) error {
	if org.IsZero() || org == ids.PlatformOrg {
		return errPlatformWebhooks
	}
	return nil
}

func overlapSeconds() int32 { return int32(WebhookKeyOverlap / time.Second) }

// EnsureWebhookKey returns the kid of org's ACTIVE webhooks key, creating
// (and auditing) it when the org has none.
func (w *WebhookKeys) EnsureWebhookKey(ctx context.Context, org ids.OrgID) (string, error) {
	if err := tenantOrg(org); err != nil {
		return "", err
	}
	var kid string
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListWebhookKeys(ctx, overlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State == string(keys.StateActive) {
				kid = r.Kid
				return nil
			}
		}
		kid, err = createSigningKey(ctx, tx, w.kp, nil, keys.PurposeWebhooks, Actor)
		return err
	})
	return kid, err
}

// SignWebhook signs content with org's ACTIVE webhooks key, and with no
// other org's (HR-511).
func (w *WebhookKeys) SignWebhook(ctx context.Context, org ids.OrgID, content []byte) ([]byte, error) {
	if err := tenantOrg(org); err != nil {
		return nil, err
	}
	w.mu.Lock()
	c, ok := w.cache[org]
	w.mu.Unlock()
	if !ok || w.now().Sub(c.at) > webhookKeyCache {
		var err error
		if c, err = w.load(ctx, org); err != nil {
			return nil, err
		}
		w.mu.Lock()
		w.cache[org] = c
		w.mu.Unlock()
	}
	return ed25519.Sign(c.priv, content), nil
}

// load unwraps org's ACTIVE webhooks key.
func (w *WebhookKeys) load(ctx context.Context, org ids.OrgID) (cachedWebhookKey, error) {
	var c cachedWebhookKey
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListWebhookKeys(ctx, overlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State != string(keys.StateActive) {
				continue
			}
			seed, err := unwrapStored(ctx, w.kp, r.KekID, r.WrappedPrivateKey, signingAAD(org, keys.PurposeWebhooks, r.Kid))
			if err != nil {
				return fmt.Errorf("keystore: unwrap webhook key %s: %w", r.Kid, err)
			}
			if len(seed) != ed25519.SeedSize {
				return fmt.Errorf("keystore: webhook key %s has a malformed seed", r.Kid)
			}
			priv := ed25519.NewKeyFromSeed(seed)
			if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(r.PublicKey)) ||
				r.Kid != keys.KIDFor(keys.PurposeWebhooks, r.PublicKey) {
				return fmt.Errorf("keystore: webhook key %s does not match its public key", r.Kid)
			}
			c = cachedWebhookKey{kid: r.Kid, priv: priv, at: w.now()}
			return nil
		}
		return ErrNoWebhookKey
	}, db.ReadOnly())
	return c, err
}

// ListWebhookKeys returns org's ACTIVE key and its RETIRING key while the
// overlap lasts, the ACTIVE one first; an expired RETIRING key is gone
// (HR-512).
func (w *WebhookKeys) ListWebhookKeys(ctx context.Context, org ids.OrgID) ([]WebhookKey, error) {
	if err := tenantOrg(org); err != nil {
		return nil, err
	}
	var out []WebhookKey
	err := w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListWebhookKeys(ctx, overlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if !r.Live {
				continue
			}
			k := WebhookKey{KID: r.Kid, State: keys.State(r.State), Public: ed25519.PublicKey(r.PublicKey), CreatedAt: r.CreatedAt}
			if k.State == keys.StateRetiring {
				k.RetiresAt = r.RetiresAt
			}
			out = append(out, k)
		}
		return nil
	}, db.ReadOnly())
	slices.SortStableFunc(out, func(a, b WebhookKey) int {
		if (a.State == keys.StateActive) != (b.State == keys.StateActive) {
			if a.State == keys.StateActive {
				return -1
			}
			return 1
		}
		return strings.Compare(a.KID, b.KID)
	})
	return out, err
}

// WebhookJWKS is org's webhook JWKS document: its ACTIVE and live RETIRING
// webhooks keys, sorted by kid, and no other org's (HR-511, HR-512).
func (w *WebhookKeys) WebhookJWKS(ctx context.Context, org ids.OrgID) ([]byte, error) {
	ks, err := w.ListWebhookKeys(ctx, org)
	if err != nil {
		return nil, err
	}
	set := make([]jws.JWK, 0, len(ks))
	for _, k := range ks {
		set = append(set, jws.PublicJWK(k.Public, k.KID))
	}
	slices.SortFunc(set, func(a, b jws.JWK) int { return strings.Compare(a.Kid, b.Kid) })
	return json.Marshal(struct {
		Keys []jws.JWK `json:"keys"`
	}{Keys: set})
}

// RotateWebhookKey moves org's ACTIVE webhooks key to RETIRING (it stays
// in the JWKS for WebhookKeyOverlap) and creates a new ACTIVE key, audited
// with actor. A RETIRING key whose overlap ended is revoked first; one
// still in its overlap refuses the rotation (ErrWebhookKeyRotating), so an
// org has at most one ACTIVE and one RETIRING key (D261). It returns the
// new kid and the retiring one ("" when the org had no key). inTx, when
// set, runs in the same transaction after the rotation (the caller's
// step-up check and audit): its error undoes the rotation.
func (w *WebhookKeys) RotateWebhookKey(ctx context.Context, org ids.OrgID, actor domain.Actor,
	inTx func(ctx context.Context, tx db.TenantTx, newKID, retiringKID string) error,
) (newKID, retiringKID string, err error) {
	if err := tenantOrg(org); err != nil {
		return "", "", err
	}
	err = w.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		newKID, retiringKID = "", ""
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListWebhookKeys(ctx, overlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State != string(keys.StateRetiring) {
				continue
			}
			if r.Live {
				return ErrWebhookKeyRotating
			}
			if err := db.ExpectOneRow(q.TransitionSigningKey(ctx, dbq.TransitionSigningKeyParams{
				OrgID: org, Kid: r.Kid, FromState: string(keys.StateRetiring), ToState: string(keys.StateRevoked),
			})); err != nil {
				return err
			}
			if _, err := audit.Record(ctx, tx, audit.Event{
				Name: "signing_key.revoked", Actor: actor, Outcome: audit.Success,
				Object:  &audit.Object{Type: "signing_key", ID: r.Kid},
				Details: map[string]string{"purpose": string(keys.PurposeWebhooks), "reason": "overlap_ended"},
			}); err != nil {
				return err
			}
		}
		for _, r := range rows {
			if r.State == string(keys.StateActive) {
				retiringKID = r.Kid
			}
		}
		all, err := q.ListSigningKeys(ctx, org)
		if err != nil {
			return err
		}
		if newKID, err = rotateIn(ctx, tx, q, w.kp, all, keys.PurposeWebhooks, actor); err != nil {
			return err
		}
		if inTx != nil {
			return inTx(ctx, tx, newKID, retiringKID)
		}
		return nil
	})
	if err != nil {
		return "", "", err
	}
	w.mu.Lock()
	delete(w.cache, org)
	w.mu.Unlock()
	return newKID, retiringKID, nil
}
