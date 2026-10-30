// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package keystore

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"sync"

	"github.com/jackc/pgx/v5"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)

// maxCachedDEKs bounds the in-memory cache of unwrapped DEKs.
const maxCachedDEKs = 10_000

// DEKStore implements crypto.DEKSource with DEKs stored wrapped by a KEK.
// Unwrapped DEKs are cached in memory (bounded).
type DEKStore struct {
	pool *db.Pool
	kp   keys.KeyProvider

	mu    sync.Mutex
	cache map[dekRef]pclog.Secret[[]byte]
}

type dekRef struct {
	org     ids.OrgID
	purpose string
	version uint32
}

var _ pccrypto.DEKSource = (*DEKStore)(nil)

// NewDEKStore returns a DEK store.
func NewDEKStore(pool *db.Pool, kp keys.KeyProvider) *DEKStore {
	return &DEKStore{pool: pool, kp: kp, cache: map[dekRef]pclog.Secret[[]byte]{}}
}

func dekAAD(org ids.OrgID, purpose string, version uint32) []byte {
	return []byte("pc-dek-v1|" + org.String() + "|" + purpose + "|" + strconv.FormatUint(uint64(version), 10))
}

// CurrentDEK returns the active DEK of (org, purpose), creating version 1 on
// first use. Creation is serialized per org and audited.
func (s *DEKStore) CurrentDEK(ctx context.Context, org ids.OrgID, purpose string) (uint32, pclog.Secret[[]byte], error) {
	if !purposePattern.MatchString(purpose) {
		return 0, pclog.Secret[[]byte]{}, fmt.Errorf("keystore: invalid DEK purpose %q", purpose)
	}
	var version uint32
	var key pclog.Secret[[]byte]
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.ActiveDEK(ctx, org, purpose)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := q.LockKeystore(ctx, org.UUID()); err != nil {
				return err
			}
			row, err = q.ActiveDEK(ctx, org, purpose) // re-check under the lock
			if errors.Is(err, pgx.ErrNoRows) {
				version, key, err = s.create(ctx, tx, purpose)
				return err
			}
		}
		if err != nil {
			return err
		}
		version = uint32(row.Version) //nolint:gosec // G115: versions are positive (CHECK constraint)
		key, err = s.unwrap(ctx, org, purpose, version, row.KekID, row.WrappedKey)
		return err
	})
	return version, key, err
}

func (s *DEKStore) create(ctx context.Context, tx db.TenantTx, purpose string) (uint32, pclog.Secret[[]byte], error) {
	q := dbq.New(tx)
	next, err := q.NextDEKVersion(ctx, tx.OrgID(), purpose)
	if err != nil {
		return 0, pclog.Secret[[]byte]{}, err
	}
	version := uint32(next) //nolint:gosec // G115: positive by construction
	plain := pccrypto.NewKey()
	wrapped, err := s.kp.Wrap(ctx, plain, dekAAD(tx.OrgID(), purpose, version))
	if err != nil {
		return 0, pclog.Secret[[]byte]{}, fmt.Errorf("keystore: wrap DEK: %w", err)
	}
	if err := q.InsertDEK(ctx, dbq.InsertDEKParams{
		OrgID: tx.OrgID(), Purpose: purpose, Version: next, WrappedKey: wrapped, KekID: s.kp.CurrentKEK(),
	}); err != nil {
		return 0, pclog.Secret[[]byte]{}, fmt.Errorf("keystore: insert DEK: %w", err)
	}
	if _, err := audit.Record(ctx, tx, audit.Event{
		Name: "dek.created", Actor: Actor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "dek", ID: purpose + "/" + strconv.FormatUint(uint64(version), 10)},
		Details: map[string]string{"purpose": purpose, "kek_id": s.kp.CurrentKEK()},
	}); err != nil {
		return 0, pclog.Secret[[]byte]{}, err
	}
	key := pclog.NewSecret(plain)
	s.put(dekRef{tx.OrgID(), purpose, version}, key)
	return version, key, nil
}

// DEK returns a specific DEK version, or crypto.ErrUnknownDEK.
func (s *DEKStore) DEK(ctx context.Context, org ids.OrgID, purpose string, version uint32) (pclog.Secret[[]byte], error) {
	if k, ok := s.get(dekRef{org, purpose, version}); ok {
		return k, nil
	}
	var key pclog.Secret[[]byte]
	err := s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetDEK(ctx, org, purpose, int32(version)) //nolint:gosec // G115: stored versions fit int32
		if errors.Is(err, pgx.ErrNoRows) {
			return pccrypto.ErrUnknownDEK
		}
		if err != nil {
			return err
		}
		key, err = s.unwrap(ctx, org, purpose, version, row.KekID, row.WrappedKey)
		return err
	}, db.ReadOnly())
	return key, err
}

func (s *DEKStore) unwrap(ctx context.Context, org ids.OrgID, purpose string, version uint32, kekID string, wrapped []byte) (pclog.Secret[[]byte], error) {
	ref := dekRef{org, purpose, version}
	if k, ok := s.get(ref); ok {
		return k, nil
	}
	plain, err := unwrapStored(ctx, s.kp, kekID, wrapped, dekAAD(org, purpose, version))
	if err != nil {
		return pclog.Secret[[]byte]{}, fmt.Errorf("keystore: unwrap DEK %s/%d: %w", purpose, version, err)
	}
	if len(plain) != pccrypto.KeySize {
		return pclog.Secret[[]byte]{}, fmt.Errorf("keystore: DEK %s/%d has the wrong size", purpose, version)
	}
	key := pclog.NewSecret(plain)
	s.put(ref, key)
	return key, nil
}

func (s *DEKStore) get(ref dekRef) (pclog.Secret[[]byte], bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.cache[ref]
	return k, ok
}

func (s *DEKStore) put(ref dekRef, k pclog.Secret[[]byte]) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= maxCachedDEKs {
		clear(s.cache)
	}
	s.cache[ref] = k
}
