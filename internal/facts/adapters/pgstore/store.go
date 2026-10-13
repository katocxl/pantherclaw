// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgstore stores fact providers and facts in PostgreSQL (HR-160):
// the facts/app Store port, the fact catalog policies compile against, and
// the facts the decision pipeline reads about a subject.
package pgstore

import (
	"context"
	"encoding/json/jsontext"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/facts/app"
	"github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Store implements app.Store.
type Store struct {
	Pool *db.Pool
}

var (
	_ app.Store = (*Store)(nil)
	_ app.Reads = (*Store)(nil)
)

// Taken implements app.Store.
func (s *Store) Taken(ctx context.Context, org ids.OrgID) (func(string) bool, error) {
	cat, err := s.Catalog(ctx, org)
	if err != nil {
		return nil, err
	}
	used := map[string]bool{}
	for n := range cat {
		used[domain.CELName(n)] = true
	}
	return func(name string) bool { return used[domain.CELName(name)] }, nil
}

// CreateProvider implements app.Store.
func (s *Store) CreateProvider(ctx context.Context, org ids.OrgID, p domain.Provider, createdBy string, ev audit.Event) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.InsertFactProvider(ctx, dbq.InsertFactProviderParams{
			OrgID: org, ID: p.ID, Name: p.Name, ServiceAccountID: opt(p.ServiceAccountID), GatewayID: opt(p.GatewayID),
			ConnectionID: opt(p.ConnectionID), CreatedBy: createdBy,
		}); err != nil {
			return err
		}
		for _, d := range p.Facts {
			if err := q.InsertFactDeclaration(ctx, dbq.InsertFactDeclarationParams{
				OrgID: org, ProviderID: p.ID, Name: d.Name, ValueType: string(d.Type), SubjectType: d.SubjectType,
				MaxLagS: int32(d.MaxLag / time.Second), //nolint:gosec // at most a day
			}); err != nil {
				return err
			}
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
	switch {
	case db.IsForeignKeyViolation(err):
		return app.ErrServiceAccountUnknown
	case db.IsUniqueViolation(err):
		return app.ErrProviderExists
	}
	return err
}

// DisableProvider implements app.Store.
func (s *Store) DisableProvider(ctx context.Context, org ids.OrgID, id ids.UUID, ev audit.Event) error {
	return s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := db.ExpectOneRow(q.DisableFactProvider(ctx, org, id)); err != nil {
			return app.ErrNotFound
		}
		if err := q.DeactivateFactDeclarations(ctx, org, id); err != nil {
			return err
		}
		_, err := audit.Record(ctx, tx, ev)
		return err
	})
}

// ProviderFor implements app.Store.
func (s *Store) ProviderFor(ctx context.Context, org ids.OrgID, serviceAccount ids.UUID) (domain.Provider, error) {
	var p domain.Provider
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetFactProviderByAccount(ctx, org, serviceAccount)
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		decls, err := q.ListFactDeclarations(ctx, org, row.ID)
		if err != nil {
			return err
		}
		p = domain.Provider{ID: row.ID, Org: org, Name: row.Name, ServiceAccountID: val(row.ServiceAccountID), State: domain.ProviderState(row.State)}
		for _, d := range decls {
			p.Facts = append(p.Facts, domain.Declaration{
				Name: d.Name, Type: domain.Type(d.ValueType), SubjectType: d.SubjectType,
				MaxLag: time.Duration(d.MaxLagS) * time.Second,
			})
		}
		return nil
	})
	return p, err
}

// Now implements app.Store.
func (s *Store) Now(ctx context.Context, org ids.OrgID) (time.Time, error) {
	var now time.Time
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		now, err = dbq.New(tx).DBNow(ctx)
		return err
	})
	return now, err
}

// Latest implements app.Store.
func (s *Store) Latest(ctx context.Context, org ids.OrgID, name, subjectType, subjectID string) (*domain.Fact, error) {
	var out *domain.Fact
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		at, err := dbq.New(tx).GetFact(ctx, dbq.GetFactParams{OrgID: org, Name: name, SubjectType: subjectType, SubjectID: subjectID})
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &domain.Fact{Name: name, SubjectType: subjectType, SubjectID: subjectID, ObservedAt: at}
		return nil
	})
	return out, err
}

// Put implements app.Store.
func (s *Store) Put(ctx context.Context, org ids.OrgID, f domain.Fact) (bool, error) {
	raw, err := domain.EncodeValue(f.Value)
	if err != nil {
		return false, err
	}
	var wrote bool
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		tag, err := dbq.New(tx).PutFact(ctx, dbq.PutFactParams{
			OrgID: org, ID: ids.NewV7(), Name: f.Name, SubjectType: f.SubjectType, SubjectID: f.SubjectID,
			ProviderID: f.ProviderID, Value: raw, ObservedAt: f.ObservedAt,
		})
		wrote = tag.RowsAffected() == 1
		return err
	})
	return wrote, err
}

// Catalog returns the active fact names and their types (what policies
// compile against).
func (s *Store) Catalog(ctx context.Context, org ids.OrgID) (map[string]domain.Type, error) {
	var out map[string]domain.Type
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.CatalogInTx(ctx, tx, org)
		return err
	})
	return out, err
}

// CatalogInTx is Catalog inside the caller's transaction (the Authority's
// one-snapshot read).
func (s *Store) CatalogInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) (map[string]domain.Type, error) {
	out := map[string]domain.Type{}
	rows, err := dbq.New(tx).ListActiveFactCatalog(ctx, org)
	for _, r := range rows {
		out[r.Name] = domain.Type(r.ValueType)
	}
	return out, err
}

// Subject returns the current facts of active providers about one subject,
// by name. A stored value that no longer decodes is left out (missing, so
// CANNOT_AUTHORIZE), never guessed.
func (s *Store) Subject(ctx context.Context, q *dbq.Queries, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]domain.Fact, error) {
	rows, err := q.ListSubjectFacts(ctx, dbq.ListSubjectFactsParams{OrgID: org, SubjectType: subjectType, SubjectID: subjectID, Names: names})
	if err != nil {
		return nil, err
	}
	out := map[string]domain.Fact{}
	for _, r := range rows {
		v, err := domain.DecodeValue(domain.Type(r.ValueType), jsontext.Value(r.Value))
		if err != nil || strings.TrimSpace(r.Name) == "" {
			continue
		}
		out[r.Name] = domain.Fact{
			Name: r.Name, SubjectType: subjectType, SubjectID: subjectID, Value: v,
			ObservedAt: r.ObservedAt, RecordedAt: r.RecordedAt, ProviderID: r.ProviderID,
		}
	}
	return out, nil
}

// ListProviders implements app.Store: providers by name, with every
// declaration (a disabled provider's are inactive).
func (s *Store) ListProviders(ctx context.Context, org ids.OrgID, includeDisabled bool) ([]domain.Provider, error) {
	var out []domain.Provider
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListFactProviders(ctx, org, includeDisabled)
		if err != nil || len(rows) == 0 {
			return err
		}
		provIDs := make([]ids.UUID, 0, len(rows))
		at := map[ids.UUID]int{}
		for i, r := range rows {
			provIDs = append(provIDs, r.ID)
			at[r.ID] = i
			out = append(out, domain.Provider{
				ID: r.ID, Org: org, Name: r.Name, ServiceAccountID: val(r.ServiceAccountID), GatewayID: val(r.GatewayID),
				ConnectionID: val(r.ConnectionID), State: domain.ProviderState(r.State),
			})
		}
		decls, err := q.ListProviderDeclarations(ctx, org, provIDs)
		if err != nil {
			return err
		}
		for _, d := range decls {
			p := &out[at[d.ProviderID]]
			p.Facts = append(p.Facts, domain.Declaration{
				Name: d.Name, Type: domain.Type(d.ValueType), SubjectType: d.SubjectType, MaxLag: time.Duration(d.MaxLagS) * time.Second,
			})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// About implements app.Store: the recorded facts of active providers
// about one subject, with their stored values.
func (s *Store) About(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) ([]app.Recorded, error) {
	if names == nil {
		names = []string{}
	}
	var out []app.Recorded
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		rows, err := dbq.New(tx).ListFactsAbout(ctx, dbq.ListFactsAboutParams{
			OrgID: org, SubjectType: subjectType, SubjectID: subjectID, Names: names,
		})
		for _, r := range rows {
			out = append(out, app.Recorded{
				Name: r.Name, SubjectType: subjectType, SubjectID: subjectID, Value: r.Value,
				ObservedAt: r.ObservedAt, RecordedAt: r.RecordedAt, ProviderID: r.ProviderID,
			})
		}
		return err
	}, db.ReadOnly())
	return out, err
}

// opt is a nullable id: nil for the zero id.
func opt(u ids.UUID) *ids.UUID {
	if u.IsZero() {
		return nil
	}
	return &u
}

// val is a nullable id's value: the zero id for nil.
func val(u *ids.UUID) ids.UUID {
	if u == nil {
		return ids.UUID{}
	}
	return *u
}

// ProviderForConnection implements app.Store: the active provider a
// gateway reports a connection's facts as (G0 M8 decision 5).
func (s *Store) ProviderForConnection(ctx context.Context, org ids.OrgID, connection ids.UUID) (domain.Provider, error) {
	var p domain.Provider
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		row, err := q.GetFactProviderByConnection(ctx, org, connection)
		if db.IsNoRows(err) {
			return app.ErrNotFound
		}
		if err != nil {
			return err
		}
		decls, err := q.ListFactDeclarations(ctx, org, row.ID)
		if err != nil {
			return err
		}
		p = domain.Provider{
			ID: row.ID, Org: org, Name: row.Name, GatewayID: val(row.GatewayID), ConnectionID: val(row.ConnectionID),
			State: domain.ProviderState(row.State),
		}
		for _, d := range decls {
			p.Facts = append(p.Facts, domain.Declaration{
				Name: d.Name, Type: domain.Type(d.ValueType), SubjectType: d.SubjectType, MaxLag: time.Duration(d.MaxLagS) * time.Second,
			})
		}
		return nil
	}, db.ReadOnly())
	return p, err
}
