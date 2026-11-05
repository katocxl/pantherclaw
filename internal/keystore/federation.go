// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Federation key lifecycle (G0 M35 D1020; HR-770).
const (
	// FederationKeyOverlap is how long a rotated federation key stays
	// RETIRING: it still signs the federation document beside the new key,
	// so peers pin the new key from a document a pinned key signed.
	FederationKeyOverlap = 7 * 24 * time.Hour
	// federationKeyCache is how long a process signs with unwrapped keys
	// before reading the org's keys again.
	federationKeyCache = time.Minute
	// FederationKIDPrefix starts every federation kid: "fed-" and the
	// key's RFC 7638 thumbprint.
	FederationKIDPrefix = "fed-"
)

// Federation key states.
const (
	FederationKeyActive   = "ACTIVE"
	FederationKeyRetiring = "RETIRING"
	FederationKeyRetired  = "RETIRED"
)

// Federation key errors.
var (
	// ErrFederationKeyRotating refuses a rotation while a RETIRING key is
	// still in its overlap.
	ErrFederationKeyRotating = errors.New("keystore: the previous federation key is still retiring")
	// ErrNoFederationKey reports an org without an ACTIVE federation key.
	ErrNoFederationKey = errors.New("keystore: the org has no federation key")
)

// FederationKey is the public view of one of an org's federation keys.
type FederationKey struct {
	KID       string
	State     string
	Public    ed25519.PublicKey
	CreatedAt time.Time
	// RetiresAt is when a RETIRING key stops signing (zero for ACTIVE).
	RetiresAt time.Time
}

// FederationKIDFor is the kid of a federation public key.
func FederationKIDFor(pub ed25519.PublicKey) string {
	return FederationKIDPrefix + jws.Thumbprint(pub)
}

func federationAAD(org ids.OrgID, kid string) []byte {
	return []byte("pc-federation-key-v1|" + org.String() + "|" + kid)
}

func federationOverlapSeconds() int32 { return int32(FederationKeyOverlap / time.Second) }

// oneRow turns an :execrows result that must touch exactly one row into an
// error.
func oneRow(n int64, err error) error {
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("keystore: expected one row, changed %d", n)
	}
	return nil
}

// FederationKeys keeps each organization's Ed25519 federation keys in
// pc.federation_keys under that org (RLS), wrapped with an AAD that binds
// the org and the kid, so a key signs only its own org's federation
// documents, confirmations, tokens and receipts (HR-062, HR-770).
type FederationKeys struct {
	pool *db.Pool
	kp   keys.KeyProvider
	now  func() time.Time

	mu    sync.Mutex
	cache map[ids.OrgID]cachedFederationKeys
}

type cachedFederationKeys struct {
	// signers are the live keys, the ACTIVE one first.
	signers []*jws.Signer
	// card is the ACTIVE key, for the listing cards (a2a.Sign, D1023).
	card ed25519.PrivateKey
	at   time.Time
}

// NewFederationKeys returns the per-org federation key store.
func NewFederationKeys(pool *db.Pool, kp keys.KeyProvider) *FederationKeys {
	return &FederationKeys{pool: pool, kp: kp, now: time.Now, cache: map[ids.OrgID]cachedFederationKeys{}}
}

func (f *FederationKeys) forget(org ids.OrgID) {
	f.mu.Lock()
	delete(f.cache, org)
	f.mu.Unlock()
}

// createFederationKey creates and stores a new ACTIVE key for tx's org.
func createFederationKey(ctx context.Context, tx db.TenantTx, kp keys.KeyProvider, createdBy string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	kid := FederationKIDFor(pub)
	jwk, err := json.Marshal(jws.PublicJWK(pub, kid))
	if err != nil {
		return "", err
	}
	wrapped, err := kp.Wrap(ctx, priv.Seed(), federationAAD(tx.OrgID(), kid))
	if err != nil {
		return "", fmt.Errorf("keystore: wrap: %w", err)
	}
	if err := dbq.New(tx).InsertFederationKey(ctx, dbq.InsertFederationKeyParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), Kid: kid, PublicKey: pub, PublicJwk: jwk,
		WrappedPrivateKey: wrapped, KekID: kp.CurrentKEK(), CreatedBy: createdBy,
	}); err != nil {
		return "", fmt.Errorf("keystore: insert federation key: %w", err)
	}
	return kid, nil
}

// retireExpired moves the RETIRING keys in rows whose overlap has ended to
// RETIRED, each audited federation.key_retired.
func retireExpired(ctx context.Context, tx db.TenantTx, q *dbq.Queries, rows []dbq.ListFederationKeysRow, actor domain.Actor) error {
	for _, r := range rows {
		if r.State != FederationKeyRetiring || r.Live {
			continue
		}
		if err := oneRow(q.TransitionFederationKey(ctx, dbq.TransitionFederationKeyParams{
			OrgID: tx.OrgID(), Kid: r.Kid, FromState: FederationKeyRetiring, ToState: FederationKeyRetired,
		})); err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: auditkind.FederationKeyRetired, Actor: actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "federation_key", ID: r.Kid},
			Details: map[string]string{"reason": "overlap_ended"},
		}); err != nil {
			return err
		}
	}
	return nil
}

// EnsureFederationKey returns the kid of org's ACTIVE federation key,
// creating (and auditing) it when the org has none.
func (f *FederationKeys) EnsureFederationKey(ctx context.Context, org ids.OrgID) (string, error) {
	if err := tenantOrg(org); err != nil {
		return "", err
	}
	var kid string
	created := false
	err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListFederationKeys(ctx, federationOverlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State == FederationKeyActive {
				kid = r.Kid
				return nil
			}
		}
		created = true
		if kid, err = createFederationKey(ctx, tx, f.kp, Actor.ID); err != nil {
			return err
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: auditkind.SigningKeyCreated, Actor: Actor, Outcome: audit.Success,
			Object:  &audit.Object{Type: "federation_key", ID: kid},
			Details: map[string]string{"purpose": "federation", "algorithm": string(keys.AlgEdDSA), "kek_id": f.kp.CurrentKEK()},
		})
		return err
	})
	if created && err == nil {
		f.forget(org)
	}
	return kid, err
}

// ListFederationKeys returns org's ACTIVE key and its RETIRING key while the
// overlap lasts, the ACTIVE one first.
func (f *FederationKeys) ListFederationKeys(ctx context.Context, org ids.OrgID) ([]FederationKey, error) {
	if err := tenantOrg(org); err != nil {
		return nil, err
	}
	var out []FederationKey
	err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListFederationKeys(ctx, federationOverlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if !r.Live {
				continue
			}
			k := FederationKey{KID: r.Kid, State: r.State, Public: ed25519.PublicKey(r.PublicKey), CreatedAt: r.CreatedAt}
			if k.State == FederationKeyRetiring {
				k.RetiresAt = r.RetiresAt
			}
			out = append(out, k)
		}
		return nil
	}, db.ReadOnly())
	slices.SortStableFunc(out, func(a, b FederationKey) int {
		switch {
		case a.State == b.State:
			return 0
		case a.State == FederationKeyActive:
			return -1
		}
		return 1
	})
	return out, err
}

// FederationCardKey returns org's ACTIVE federation key and its kid, for
// signing its listing cards (G0 M35 D1023); nothing else uses it.
func (f *FederationKeys) FederationCardKey(ctx context.Context, org ids.OrgID) (string, ed25519.PrivateKey, error) {
	signers, err := f.FederationSigners(ctx, org)
	if err != nil {
		return "", nil, err
	}
	f.mu.Lock()
	c := f.cache[org]
	f.mu.Unlock()
	if c.card == nil || len(signers) == 0 || len(c.signers) == 0 {
		return "", nil, ErrNoFederationKey
	}
	return c.signers[0].KeyID(), c.card, nil
}

// FederationSigners returns signers for org's live federation keys, the
// ACTIVE one first: the document is signed by every one of them, anything
// else by the first only. An org without an ACTIVE key gets one.
func (f *FederationKeys) FederationSigners(ctx context.Context, org ids.OrgID) ([]*jws.Signer, error) {
	if err := tenantOrg(org); err != nil {
		return nil, err
	}
	f.mu.Lock()
	c, ok := f.cache[org]
	f.mu.Unlock()
	if ok && f.now().Sub(c.at) <= federationKeyCache {
		return c.signers, nil
	}
	if _, err := f.EnsureFederationKey(ctx, org); err != nil {
		return nil, err
	}
	var signers []*jws.Signer
	var card ed25519.PrivateKey
	err := f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListFederationKeys(ctx, federationOverlapSeconds(), org)
		if err != nil {
			return err
		}
		var active *jws.Signer
		for _, r := range rows {
			if !r.Live {
				continue
			}
			seed, err := unwrapStored(ctx, f.kp, r.KekID, r.WrappedPrivateKey, federationAAD(org, r.Kid))
			if err != nil {
				return fmt.Errorf("keystore: unwrap federation key %s: %w", r.Kid, err)
			}
			if len(seed) != ed25519.SeedSize {
				return fmt.Errorf("keystore: federation key %s has a malformed seed", r.Kid)
			}
			priv := ed25519.NewKeyFromSeed(seed)
			if !priv.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(r.PublicKey)) || r.Kid != FederationKIDFor(r.PublicKey) {
				return fmt.Errorf("keystore: federation key %s does not match its public key", r.Kid)
			}
			s, err := jws.NewSigner(r.Kid, priv)
			if err != nil {
				return err
			}
			if r.State == FederationKeyActive {
				active, card = s, priv
			} else {
				signers = append(signers, s)
			}
		}
		if active == nil {
			return ErrNoFederationKey
		}
		signers = append([]*jws.Signer{active}, signers...)
		return nil
	}, db.ReadOnly())
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if len(f.cache) >= maxCachedJWKS {
		f.cache = map[ids.OrgID]cachedFederationKeys{}
	}
	f.cache[org] = cachedFederationKeys{signers: signers, card: card, at: f.now()}
	f.mu.Unlock()
	return signers, nil
}

// RotateFederationKey moves org's ACTIVE federation key to RETIRING (it
// keeps co-signing the document for FederationKeyOverlap) and creates a new
// ACTIVE key. A RETIRING key whose overlap ended is retired first; one
// still in its overlap refuses the rotation (ErrFederationKeyRotating). It
// returns the new kid and the retiring one ("" when the org had no key).
// inTx runs in the same transaction after the rotation (the caller's
// step-up check and audit): its error undoes the rotation.
func (f *FederationKeys) RotateFederationKey(ctx context.Context, org ids.OrgID, actor domain.Actor,
	inTx func(ctx context.Context, tx db.TenantTx, newKID, retiringKID string) error,
) (newKID, retiringKID string, err error) {
	if err := tenantOrg(org); err != nil {
		return "", "", err
	}
	err = f.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		newKID, retiringKID = "", ""
		q := dbq.New(tx)
		if err := q.LockKeystore(ctx, org.UUID()); err != nil {
			return err
		}
		rows, err := q.ListFederationKeys(ctx, federationOverlapSeconds(), org)
		if err != nil {
			return err
		}
		for _, r := range rows {
			if r.State == FederationKeyRetiring && r.Live {
				return ErrFederationKeyRotating
			}
		}
		if err := retireExpired(ctx, tx, q, rows, actor); err != nil {
			return err
		}
		for _, r := range rows {
			if r.State != FederationKeyActive {
				continue
			}
			retiringKID = r.Kid
			if err := oneRow(q.TransitionFederationKey(ctx, dbq.TransitionFederationKeyParams{
				OrgID: org, Kid: r.Kid, FromState: FederationKeyActive, ToState: FederationKeyRetiring,
			})); err != nil {
				return err
			}
		}
		if newKID, err = createFederationKey(ctx, tx, f.kp, actor.ID); err != nil {
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
	f.forget(org)
	return newKID, retiringKID, nil
}

// rewrapFederationKeys re-wraps up to RewrapBatch of org's federation keys
// not under cur, as RewrapOrg does for pc.keys (D1024a): pc_keystore writes,
// pc_app audits.
func rewrapFederationKeys(ctx context.Context, pool, ks *db.Pool, kp keys.KeyProvider, org ids.OrgID, cur []string) (int, error) {
	var rows []dbq.ListFederationKeysToRewrapRow
	err := pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		rows, err = dbq.New(tx).ListFederationKeysToRewrap(ctx, org, cur, RewrapBatch)
		return err
	}, db.ReadOnly())
	if err != nil {
		return 0, err
	}
	if ks == nil {
		if len(rows) > 0 {
			return 0, ErrRewrapNotConfigured
		}
		return 0, nil
	}
	n := 0
	for _, k := range rows {
		if err := rewrapOne(ctx, pool, ks, kp, org, k.KekID, k.WrappedPrivateKey, federationAAD(org, k.Kid), "federation_key", k.Kid,
			func(q *dbq.Queries, wrapped []byte, kek string) (int64, error) {
				return q.RewrapFederationKey(ctx, dbq.RewrapFederationKeyParams{
					OrgID: org, Kid: k.Kid,
					OldWrappedPrivateKey: k.WrappedPrivateKey, OldKekID: k.KekID, WrappedPrivateKey: wrapped, KekID: kek,
				})
			}); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
