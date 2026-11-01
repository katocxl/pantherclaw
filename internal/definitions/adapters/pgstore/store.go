// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package pgstore stores tool packages per org in PostgreSQL: the
// definitions/app Repository port (part 1), the org package-signing keys
// (Keys, HR-162), and the definition lookups the decision pipeline and grant
// issuance need (G0 M4 part 2). The exact signed bytes are the source of
// truth; decoded packages are cached by version id (a version never
// changes).
package pgstore

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/app"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/detection/injection"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/supplychain/adapters/pgflags"
	scdomain "github.com/katocxl/pantherclaw/internal/supplychain/domain"
	pgwaitlist "github.com/katocxl/pantherclaw/internal/waitlist/adapters/pgwaitlist"
)

// ErrNotFound reports a package, version or definition the org does not
// have.
var ErrNotFound = app.ErrMissing

// maxCached bounds the decoded package cache.
const maxCached = 256

// Store implements app.Repository.
type Store struct {
	Pool *db.Pool

	mu    sync.Mutex
	cache map[ids.UUID]*domain.Package
}

var _ app.Repository = (*Store)(nil)

// TrustedMetadata implements app.Repository.
func (s *Store) TrustedMetadata(ctx context.Context, org ids.OrgID) (*trust.State, error) {
	var out *trust.State
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPackageTrust(ctx, org)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &trust.State{Version: row.Version, PayloadDigest: row.PayloadDigest}
		return nil
	})
	return out, err
}

// CurrentPin implements app.Repository.
func (s *Store) CurrentPin(ctx context.Context, org ids.OrgID, pkg string) (*domain.Pin, error) {
	var out *domain.Pin
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPackagePin(ctx, org, pkg)
		if db.IsNoRows(err) {
			return nil
		}
		if err != nil {
			return err
		}
		out = &domain.Pin{Package: pkg, Version: row.Version, Digest: row.Digest}
		return nil
	})
	return out, err
}

// Import implements app.Repository: one transaction, conditional on the
// trust state and pin that were read (HR-004, HR-123).
func (s *Store) Import(ctx context.Context, org ids.OrgID, rec app.Record) error {
	canon, err := manifest.DefinitionsCanonical(rec.Raw)
	if err != nil || len(canon) != len(rec.Package.Definitions) {
		return fmt.Errorf("definitions: canonical definitions: %w", err)
	}
	err = s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		if err := q.LockPackageImports(ctx, org.String()); err != nil {
			return err
		}
		if err := checkOperations(ctx, q, org, rec); err != nil {
			return err
		}
		advance := advanceTrust
		if rec.SigningKey != nil {
			advance = advanceKeyTrust
		}
		if err := advance(ctx, q, org, rec); err != nil {
			return err
		}
		pkgID, err := q.GetToolPackageID(ctx, org, rec.Package.Name)
		if db.IsNoRows(err) {
			pkgID = ids.NewV7()
			err = q.InsertToolPackage(ctx, org, pkgID, rec.Package.Name)
		}
		if err != nil {
			return err
		}
		versionID := ids.NewV7()
		if err := q.InsertPackageVersion(ctx, dbq.InsertPackageVersionParams{
			OrgID: org, ID: versionID, PackageID: pkgID, Version: rec.Package.Version, FileDigest: rec.FileDigest,
			Raw: rec.Raw, State: string(rec.State), SigningKeyID: rec.SigningKey,
		}); err != nil {
			return err
		}
		for i, d := range rec.Package.Definitions {
			if err := q.InsertActionDefinition(ctx, dbq.InsertActionDefinitionParams{
				OrgID: org, ID: ids.NewV7(), VersionID: versionID, Operation: d.Operation, Digest: d.Digest, Canonical: canon[i],
			}); err != nil {
				return err
			}
		}
		for i, c := range rec.Package.Consequences {
			b, err := json.Marshal(c, json.Deterministic(true))
			if err != nil {
				return err
			}
			if err := q.InsertConsequenceRule(ctx, dbq.InsertConsequenceRuleParams{
				OrgID: org, ID: ids.NewV7(), VersionID: versionID, Position: int32(i), Canonical: b,
			}); err != nil {
				return err
			}
		}
		if err := advancePin(ctx, q, org, pkgID, versionID, rec); err != nil {
			return err
		}
		// Reviewed tool descriptions with instruction-like content are
		// flagged and the version goes to review (G0 M10 D47, HR-244).
		flagged, err := scanDescriptions(ctx, tx, versionID, rec)
		if err != nil {
			return err
		}
		// The supply-chain checks run before the review opens, and their
		// flags go on it (G0 M24 D212). They inform the person and change no
		// state (HR-582).
		supply, err := pgflags.CheckPackage(ctx, tx, org, versionID, rec.Package, trust.IsDevKID(rec.SigningKID))
		if err != nil {
			return err
		}
		// A version that is not active yet waits for review (G0 M5 part 2).
		if rec.State != domain.StateActive || flagged || len(supply.Flags) > 0 {
			if _, err := pgwaitlist.OpenFlaggedToolReview(ctx, tx, org, versionID, rec.Package.Name, rec.Package.Version,
				scdomain.Summary(supply), actorOf(rec.Event)); err != nil {
				return err
			}
		}
		return record(ctx, tx, rec.Event)
	})
	if db.IsUniqueViolation(err) || errors.Is(err, db.ErrLostRace) {
		return app.ErrConflict
	}
	return err
}

func advanceTrust(ctx context.Context, q *dbq.Queries, org ids.OrgID, rec app.Record) error {
	if rec.PreviousMetadata == nil {
		return q.InsertPackageTrust(ctx, dbq.InsertPackageTrustParams{
			OrgID: org, Version: rec.Metadata.Version, PayloadDigest: rec.Metadata.PayloadDigest, ExpiresAt: rec.MetadataExpiry,
		})
	}
	return db.ExpectOneRow(q.AdvancePackageTrust(ctx, dbq.AdvancePackageTrustParams{
		Version: rec.Metadata.Version, PayloadDigest: rec.Metadata.PayloadDigest, ExpiresAt: rec.MetadataExpiry,
		OrgID: org, PrevVersion: rec.PreviousMetadata.Version, PrevDigest: rec.PreviousMetadata.PayloadDigest,
	}))
}

func advancePin(ctx context.Context, q *dbq.Queries, org ids.OrgID, pkgID, versionID ids.UUID, rec app.Record) error {
	cur, err := q.GetPackagePin(ctx, org, rec.Package.Name)
	switch {
	case db.IsNoRows(err):
		if rec.PreviousPin != nil {
			return app.ErrConflict
		}
		return q.InsertPackagePin(ctx, dbq.InsertPackagePinParams{
			OrgID: org, PackageID: pkgID, VersionID: versionID, Version: rec.Pin.Version, Digest: rec.Pin.Digest,
		})
	case err != nil:
		return err
	case rec.PreviousPin == nil || cur.Version != rec.PreviousPin.Version || cur.Digest != rec.PreviousPin.Digest:
		return app.ErrConflict
	}
	return db.ExpectOneRow(q.AdvancePackagePin(ctx, dbq.AdvancePackagePinParams{
		VersionID: versionID, Version: rec.Pin.Version, Digest: rec.Pin.Digest,
		OrgID: org, PackageID: pkgID, PrevVersionID: cur.VersionID,
	}))
}

// State implements app.Repository.
func (s *Store) State(ctx context.Context, org ids.OrgID, pkg, version string) (domain.State, error) {
	var out domain.State
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).GetPackageVersionState(ctx, org, pkg, version)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		out = domain.State(row.State)
		return err
	})
	return out, err
}

// Transition implements app.Repository. Quarantining or retiring a version
// removes authority, so the same transaction first increments the org's
// containment epoch: permits already issued for it fail BeginDispatch
// (HR-002; G0 M4 part 2, design decision 8).
func (s *Store) Transition(ctx context.Context, org ids.OrgID, pkg, version string, from, to domain.State, ev *audit.Event) error {
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		return s.TransitionTx(ctx, tx, pkg, version, from, to, ev)
	})
	if errors.Is(err, db.ErrLostRace) {
		return app.ErrConflict
	}
	return err
}

// StateTx is State in the caller's transaction (a protected activation's,
// G0 M11 D42).
func (s *Store) StateTx(ctx context.Context, tx db.TenantTx, pkg, version string) (domain.State, error) {
	row, err := dbq.New(tx).GetPackageVersionState(ctx, tx.OrgID(), pkg, version)
	if db.IsNoRows(err) {
		return "", ErrNotFound
	} else if err != nil {
		return "", err
	}
	return domain.State(row.State), nil
}

// TransitionTx is Transition in the caller's transaction; a lost race is
// db.ErrLostRace.
func (s *Store) TransitionTx(ctx context.Context, tx db.TenantTx, pkg, version string, from, to domain.State, ev *audit.Event) error {
	org := tx.OrgID()
	q := dbq.New(tx)
	if to == domain.StateQuarantined || to == domain.StateRetired {
		if err := db.ExpectOneRow(q.RaiseContainmentEpoch(ctx, org)); err != nil {
			return fmt.Errorf("definitions: containment epoch: %w", err)
		}
	}
	row, err := q.GetPackageVersionState(ctx, org, pkg, version)
	if db.IsNoRows(err) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if err := db.ExpectOneRow(q.TransitionPackageVersion(ctx, dbq.TransitionPackageVersionParams{
		ToState: string(to), OrgID: org, ID: row.ID, FromState: string(from),
	})); err != nil {
		return err
	}
	if err := pgwaitlist.CloseToolReview(ctx, tx, org, row.ID, string(to), actorOf(ev).Type+":"+actorOf(ev).ID); err != nil {
		return err
	}
	if to == domain.StateActive || to == domain.StateQuarantined || to == domain.StateRetired {
		if err := pgflags.ClearPackage(ctx, tx, org, row.ID); err != nil {
			return err
		}
	}
	return record(ctx, tx, ev)
}

// Pinned returns the definition an ActionIR pins (package, version, digest)
// from the versions the org imported, with that version's lifecycle state.
func (s *Store) Pinned(ctx context.Context, org ids.OrgID, pin actionir.Definition) (*domain.Definition, domain.State, error) {
	var d *domain.Definition
	var state domain.State
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		d, state, err = s.PinnedInTx(ctx, tx, org, pin)
		return err
	})
	return d, state, err
}

// PinnedInTx is Pinned inside the caller's transaction (the Authority's
// one-snapshot read).
func (s *Store) PinnedInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, pin actionir.Definition) (*domain.Definition, domain.State, error) {
	_, d, state, err := s.PinnedPackageInTx(ctx, tx, org, pin)
	return d, state, err
}

// PinnedPackageInTx is PinnedInTx with the package version that defines the
// pinned definition, whose consequence rules the Authority evaluates with
// it (G0 M8, HR-206).
func (s *Store) PinnedPackageInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, pin actionir.Definition) (
	*domain.Package, *domain.Definition, domain.State, error,
) {
	q := dbq.New(tx)
	row, err := q.GetDefinitionVersion(ctx, dbq.GetDefinitionVersionParams{OrgID: org, Name: pin.Package, Version: pin.Version, Digest: pin.Digest})
	if db.IsNoRows(err) {
		return nil, nil, "", ErrNotFound
	}
	if err != nil {
		return nil, nil, "", err
	}
	p, err := s.decoded(ctx, q, org, row.ID)
	if err != nil {
		return nil, nil, "", err
	}
	i := slices.IndexFunc(p.Definitions, func(x domain.Definition) bool { return x.Digest == pin.Digest })
	if i < 0 {
		return nil, nil, "", ErrNotFound
	}
	return p, &p.Definitions[i], domain.State(row.State), nil
}

// Active returns the org's ACTIVE definition of an operation (the highest
// active version that defines it), or nil when there is none.
func (s *Store) Active(ctx context.Context, org ids.OrgID, op string) (*domain.Definition, error) {
	var out *domain.Definition
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		_, d, err := s.ActiveInTx(ctx, tx, org, op)
		out = d
		return err
	})
	return out, err
}

// ActiveInTx is Active in tx, with the package version that holds the
// definition, so that its pin can be recorded (G0 M17 D106): nil, nil
// when no ACTIVE version defines op.
func (s *Store) ActiveInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, op string) (*domain.Package, *domain.Definition, error) {
	q := dbq.New(tx)
	rows, err := q.ListActiveVersionsWith(ctx, org, op)
	if err != nil || len(rows) == 0 {
		return nil, nil, err
	}
	best := rows[0]
	for _, r := range rows[1:] {
		a, err1 := domain.ParseVersion(r.Version)
		b, err2 := domain.ParseVersion(best.Version)
		if err1 == nil && err2 == nil && a.Compare(b) > 0 {
			best = r
		}
	}
	p, err := s.decoded(ctx, q, org, best.ID)
	if err != nil {
		return nil, nil, err
	}
	if d, ok := p.Definition(op); ok {
		return p, d, nil
	}
	return nil, nil, nil
}

// ActiveDefinitions returns every definition of the org's ACTIVE versions
// (to compile policy bundles).
func (s *Store) ActiveDefinitions(ctx context.Context, org ids.OrgID) ([]*domain.Definition, error) {
	var out []*domain.Definition
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = s.ActiveDefinitionsInTx(ctx, tx, org)
		return err
	})
	return out, err
}

// ActiveDefinitionsInTx is ActiveDefinitions inside the caller's
// transaction.
func (s *Store) ActiveDefinitionsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) ([]*domain.Definition, error) {
	q := dbq.New(tx)
	versions, err := q.ListActiveVersions(ctx, org)
	if err != nil {
		return nil, err
	}
	var out []*domain.Definition
	for _, v := range versions {
		p, err := s.decoded(ctx, q, org, v)
		if err != nil {
			return nil, err
		}
		for i := range p.Definitions {
			out = append(out, &p.Definitions[i])
		}
	}
	return out, nil
}

// ActivePackages returns the decoded packages of the org's ACTIVE
// versions, with their consequence rules (policy scenario tests decide
// consequences as the Authority does, M11.1 D28). The returned packages
// are shared: callers must not change them.
func (s *Store) ActivePackages(ctx context.Context, org ids.OrgID) ([]*domain.Package, error) {
	var out []*domain.Package
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		versions, err := q.ListActiveVersions(ctx, org)
		if err != nil {
			return err
		}
		for _, v := range versions {
			p, err := s.decoded(ctx, q, org, v)
			if err != nil {
				return err
			}
			out = append(out, p)
		}
		return nil
	})
	return out, err
}

// ActivePackagesQ is ActivePackages through the caller's queries, inside
// its transaction (the promotion gate reads them while a grant is issued,
// G0 M11 part 2 D70). The returned packages are shared: callers must not
// change them.
func (s *Store) ActivePackagesQ(ctx context.Context, q *dbq.Queries, org ids.OrgID) ([]*domain.Package, error) {
	versions, err := q.ListActiveVersions(ctx, org)
	if err != nil {
		return nil, err
	}
	out := make([]*domain.Package, 0, len(versions))
	for _, v := range versions {
		p, err := s.decoded(ctx, q, org, v)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// VersionInTx returns the decoded package of an imported version, by its
// id, inside the caller's transaction (the Authority's one-snapshot read).
// The returned package is shared: callers must not change it.
func (s *Store) VersionInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID, version ids.UUID) (*domain.Package, error) {
	p, err := s.decoded(ctx, dbq.New(tx), org, version)
	if db.IsNoRows(err) {
		return nil, ErrNotFound
	}
	return p, err
}

// decoded returns the decoded package of a version, from the cache or by
// decoding its signed bytes (which recomputes every digest).
func (s *Store) decoded(ctx context.Context, q *dbq.Queries, org ids.OrgID, version ids.UUID) (*domain.Package, error) {
	s.mu.Lock()
	p, ok := s.cache[version]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	raw, err := q.GetPackageVersionRaw(ctx, org, version)
	if err != nil {
		return nil, err
	}
	p, err = manifest.Decode(raw)
	if err != nil {
		return nil, fmt.Errorf("definitions: stored package no longer decodes: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil || len(s.cache) >= maxCached {
		s.cache = map[ids.UUID]*domain.Package{}
	}
	s.cache[version] = p
	return p, nil
}

// actorOf is who made a change: its audit event's actor, or the system.
func actorOf(ev *audit.Event) evdomain.Actor {
	if ev == nil {
		return pgwaitlist.System
	}
	return ev.Actor
}

func record(ctx context.Context, tx db.TenantTx, ev *audit.Event) error {
	if ev == nil {
		return nil
	}
	_, err := audit.Record(ctx, tx, *ev)
	return err
}

// ListVersions implements app.Reads.
func (s *Store) ListVersions(ctx context.Context, org ids.OrgID, name string) ([]app.VersionInfo, error) {
	var out []app.VersionInfo
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		rows, err := q.ListPackageVersions(ctx, org, name)
		if err != nil || len(rows) == 0 {
			return err
		}
		versions := make([]ids.UUID, 0, len(rows))
		at := map[ids.UUID]int{}
		for i, r := range rows {
			versions = append(versions, r.ID)
			at[r.ID] = i
			v := app.VersionInfo{
				Name: r.Name, Version: r.Version, State: domain.State(r.State), FileDigest: r.FileDigest,
				Pinned: r.Pinned, ImportedAt: r.ImportedAt,
			}
			if r.SigningKid != nil {
				v.SigningKey = *r.SigningKid
			}
			out = append(out, v)
		}
		defs, err := q.ListVersionDefinitions(ctx, org, versions)
		if err != nil {
			return err
		}
		for _, d := range defs {
			v := &out[at[d.VersionID]]
			v.Definitions = append(v.Definitions, app.DefinitionRef{Operation: d.Operation, Digest: d.Digest})
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// DefinitionByDigest implements app.Reads.
func (s *Store) DefinitionByDigest(ctx context.Context, org ids.OrgID, digest string) (app.DefinitionInfo, error) {
	var out app.DefinitionInfo
	err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		r, err := dbq.New(tx).GetDefinitionByDigest(ctx, org, digest)
		if db.IsNoRows(err) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		out = app.DefinitionInfo{
			Operation: r.Operation, Digest: r.Digest, Canonical: r.Canonical, Package: r.Name, Version: r.Version,
			State: domain.State(r.State),
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// scanDescriptions scans the reviewed MCP tool descriptions of an imported
// version for instruction-like content (G0 M10 D47, HR-244) and records
// each hit. It reports whether any was flagged.
func scanDescriptions(ctx context.Context, tx db.TenantTx, version ids.UUID, rec app.Record) (bool, error) {
	flagged := false
	seen := map[string]bool{}
	for _, d := range rec.Package.Definitions {
		for _, m := range d.Mappings {
			if m.Channel != domain.ChannelMCP || m.Description == "" || seen[m.Tool+"\x00"+m.Description] {
				continue
			}
			seen[m.Tool+"\x00"+m.Description] = true
			r := injection.Scan(m.Description)
			if !r.Flagged {
				continue
			}
			flagged = true
			if err := injection.Record(ctx, tx, actorOf(rec.Event), audit.Object{Type: "package_version", ID: version.String()},
				m.Tool, "import", r, map[string]string{"package": rec.Package.Name, "version": rec.Package.Version}); err != nil {
				return false, err
			}
		}
	}
	return flagged, nil
}
