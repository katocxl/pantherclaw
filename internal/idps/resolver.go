// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package idps

import (
	"context"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oidcrp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// maxCached bounds the providers kept with their discovery; past it the
// cache starts over.
const maxCached = 1000

// Resolver implements authnapp.OrgIdPs: on each request it reads the
// org's ACTIVE providers and its "own providers only" setting, so a
// provider disabled or changed a moment ago no longer signs anyone in
// (D155). Each provider's discovery is kept while the provider is
// unchanged.
type Resolver struct {
	Pool  *db.Pool
	Store *Store
	// HTTPClient overrides the egress client (tests only).
	HTTPClient *http.Client
	Log        *slog.Logger

	mu    sync.Mutex
	cache map[cacheKey]cached
}

type cacheKey struct {
	org ids.OrgID
	id  ids.UUID
}

type cached struct {
	updated time.Time
	p       *oidcrp.Provider
}

var _ authnapp.OrgIdPs = (*Resolver)(nil)

// OrgProviders implements authnapp.OrgIdPs. A provider whose secret does
// not unseal or whose settings no longer validate is left out (logged).
func (r *Resolver) OrgProviders(ctx context.Context, org ids.OrgID) ([]authnapp.IdP, bool, error) {
	var (
		rows []dbq.ActiveOrgIdentityProvidersRow
		only bool
	)
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		var err error
		if rows, err = q.ActiveOrgIdentityProviders(ctx, org); err != nil {
			return err
		}
		only, err = r.Store.OwnOnly(ctx, tx)
		return err
	}, db.ReadOnly())
	if err != nil {
		return nil, false, err
	}
	out := make([]authnapp.IdP, 0, len(rows))
	for _, row := range rows {
		p, err := r.provider(ctx, org, row)
		if err != nil {
			r.log().WarnContext(ctx, "idps.provider_unusable", slog.String("org", org.String()),
				slog.String("provider", row.ID.String()), pclog.Err(err))
			continue
		}
		out = append(out, p)
	}
	return out, only, nil
}

func (r *Resolver) provider(ctx context.Context, org ids.OrgID, row dbq.ActiveOrgIdentityProvidersRow) (*oidcrp.Provider, error) {
	k := cacheKey{org, row.ID}
	r.mu.Lock()
	c, ok := r.cache[k]
	r.mu.Unlock()
	if ok && c.updated.Equal(row.UpdatedAt) {
		return c.p, nil
	}
	secret, err := r.Store.open(ctx, org, row.ID, row.ClientSecret)
	if err != nil {
		return nil, err
	}
	p, err := oidcrp.New(oidcrp.Config{
		Name: row.Name, Issuer: row.Issuer, ClientID: row.ClientID, ClientSecret: secret, TrustEmail: row.TrustEmail,
		HTTPClient: r.HTTPClient, Org: true,
	})
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	if r.cache == nil || len(r.cache) >= maxCached {
		r.cache = map[cacheKey]cached{}
	}
	r.cache[k] = cached{updated: row.UpdatedAt, p: p}
	r.mu.Unlock()
	return p, nil
}

func (r *Resolver) log() *slog.Logger {
	if r.Log == nil {
		return pclog.Discard()
	}
	return r.Log
}
