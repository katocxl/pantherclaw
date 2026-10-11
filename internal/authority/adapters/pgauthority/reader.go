// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgauthority

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/authority/finalize"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/budgets/adapters/pgbudgets"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	defpg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	factpg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gpg "github.com/katocxl/pantherclaw/internal/grants/adapters/pgstore"
	gapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	polpg "github.com/katocxl/pantherclaw/internal/policy/adapters/pgstore"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
)

// maxCompiled bounds the compiled-policy cache.
const maxCompiled = 128

// Reader implements pipeline.Reader over the module stores, and
// pipeline.Snapshotter: one evaluation reads everything in one transaction.
type Reader struct {
	Pool        *db.Pool
	Definitions *defpg.Store
	Policies    *polpg.Store
	FactStore   *factpg.Store
	Grants      *gpg.Store
	// Limits and Budget are the CEL limits and per-evaluation cost budget
	// (G0 M4 decision 4: server configuration).
	Limits celenv.Limits
	Budget uint64

	mu       sync.Mutex
	compiled map[string]*pipeline.Policy
}

var (
	_ pipeline.Reader      = (*Reader)(nil)
	_ pipeline.Snapshotter = (*Reader)(nil)
	_ pipeline.Reader      = (*snapshot)(nil)
	// The finalization's lookup must share the snapshot's transaction: a
	// second one from the pool while the snapshot holds a connection could
	// wait forever once every connection is held that way.
	_ finalize.Lookuper = (*snapshot)(nil)
)

// Snapshot implements pipeline.Snapshotter: every read of fn runs in one
// REPEATABLE READ, READ ONLY tenant transaction, so an evaluation sees one
// snapshot of the org and costs one transaction instead of one per read.
//
// A read that fails with a database error aborts the transaction, so every
// later read of the evaluation fails too: all of them are missing evidence
// (CANNOT_AUTHORIZE), never a pass. Nothing is written, so a COMMIT that
// fails after fn returned loses nothing and is not an error.
func (r *Reader) Snapshot(ctx context.Context, org ids.OrgID, fn func(context.Context, pipeline.Reader) error) error {
	ran := false
	var fnErr error
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		ran = true
		fnErr = fn(ctx, &snapshot{r: r, tx: tx})
		return fnErr
	}, db.RepeatableRead(), db.ReadOnly())
	if ran {
		return fnErr
	}
	return err
}

// read runs one read in a read-only transaction of its own: the Reader used
// outside a snapshot.
func read[T any](ctx context.Context, r *Reader, org ids.OrgID, fn func(context.Context, *snapshot) (T, error)) (T, error) {
	var out T
	err := r.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		var err error
		out, err = fn(ctx, &snapshot{r: r, tx: tx})
		return err
	}, db.ReadOnly())
	return out, err
}

// Containment implements pipeline.Reader.
func (r *Reader) Containment(ctx context.Context, org ids.OrgID) (pipeline.Containment, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Containment, error) { return s.Containment(ctx, org) })
}

// Definition implements pipeline.Reader.
func (r *Reader) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Pinned, error) { return s.Definition(ctx, org, pin) })
}

// Policy implements pipeline.Reader.
func (r *Reader) Policy(ctx context.Context, org ids.OrgID) (*pipeline.Policy, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (*pipeline.Policy, error) { return s.Policy(ctx, org) })
}

// Run implements pipeline.Reader.
func (r *Reader) Run(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Run, error) { return s.Run(ctx, org, id) })
}

// Connection implements pipeline.Reader.
func (r *Reader) Connection(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Connection, error) { return s.Connection(ctx, org, id) })
}

// Agent implements pipeline.Reader.
func (r *Reader) Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Agent, error) { return s.Agent(ctx, org, id) })
}

// Chain implements pipeline.Reader.
func (r *Reader) Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) ([]gdomain.Grant, error) { return s.Chain(ctx, org, id) })
}

// Envelopes implements pipeline.Reader.
func (r *Reader) Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) ([]gdomain.Envelope, error) {
		return s.Envelopes(ctx, org, scopes)
	})
}

// Facts implements pipeline.Reader.
func (r *Reader) Facts(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (map[string]fdomain.Fact, error) {
		return s.Facts(ctx, org, subjectType, subjectID, names)
	})
}

// Usage implements pipeline.Reader.
func (r *Reader) Usage(ctx context.Context, org ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (pipeline.Usage, error) { return s.Usage(ctx, org, plan) })
}

// Claim implements pipeline.Reader.
func (r *Reader) Claim(ctx context.Context, org ids.OrgID, key string) (*pipeline.Claim, error) {
	return read(ctx, r, org, func(ctx context.Context, s *snapshot) (*pipeline.Claim, error) { return s.Claim(ctx, org, key) })
}

// snapshot is a pipeline.Reader over one transaction (Reader.Snapshot).
type snapshot struct {
	r  *Reader
	tx db.TenantTx
}

func notFound(err error) error {
	if errors.Is(err, gapp.ErrNotFound) || errors.Is(err, defpg.ErrNotFound) || db.IsNoRows(err) {
		return pipeline.ErrNotFound
	}
	return err
}

// Containment implements pipeline.Reader: the epoch, the kill switch and the
// database time. An org without a containment row cannot be decided for.
func (s *snapshot) Containment(ctx context.Context, org ids.OrgID) (pipeline.Containment, error) {
	row, err := dbq.New(s.tx).GetContainmentNow(ctx, org)
	if err != nil {
		return pipeline.Containment{}, fmt.Errorf("authority: containment: %w", err)
	}
	return pipeline.Containment{Epoch: row.Epoch, KillSwitch: row.KillSwitch, Now: row.Now}, nil
}

// Definition implements pipeline.Reader.
func (s *snapshot) Definition(ctx context.Context, org ids.OrgID, pin actionir.Definition) (pipeline.Pinned, error) {
	d, state, err := s.r.Definitions.PinnedInTx(ctx, s.tx, org, pin)
	if err != nil {
		return pipeline.Pinned{}, notFound(err)
	}
	return pipeline.Pinned{Definition: d, State: state}, nil
}

// Policy implements pipeline.Reader: the published bundle compiled against
// the org's fact catalog and active definitions, cached by all three.
func (s *snapshot) Policy(ctx context.Context, org ids.OrgID) (*pipeline.Policy, error) {
	b, err := s.r.Policies.PublishedInTx(ctx, s.tx, org)
	if err != nil || b == nil {
		return nil, err
	}
	catalog, err := s.r.FactStore.CatalogInTx(ctx, s.tx, org)
	if err != nil {
		return nil, err
	}
	defs, err := s.r.Definitions.ActiveDefinitionsInTx(ctx, s.tx, org)
	if err != nil {
		return nil, err
	}
	r := s.r
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%d|", org, b.ID, b.Version)
	for _, n := range slices.Sorted(maps.Keys(catalog)) {
		fmt.Fprintf(h, "%s=%s;", n, catalog[n])
	}
	for _, d := range defs {
		fmt.Fprintf(h, "%s;", d.Digest)
	}
	key := hex.EncodeToString(h.Sum(nil))
	r.mu.Lock()
	p, ok := r.compiled[key]
	r.mu.Unlock()
	if ok {
		return p, nil
	}
	c, err := (&papp.Engine{Limits: r.Limits, Facts: catalog}).Compile(b, defs)
	if err != nil {
		return nil, fmt.Errorf("authority: the published policy does not compile: %w", err)
	}
	budget := r.Budget
	if budget == 0 {
		budget = papp.DefaultBudget
	}
	p = &pipeline.Policy{Compiled: c, Version: fmt.Sprintf("%s@%d", b.ID, b.Version), Budget: budget}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.compiled == nil || len(r.compiled) >= maxCompiled {
		r.compiled = map[string]*pipeline.Policy{}
	}
	r.compiled[key] = p
	return p, nil
}

// Run implements pipeline.Reader.
func (s *snapshot) Run(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Run, error) {
	row, err := dbq.New(s.tx).SubjectRun(ctx, org, id)
	if err != nil {
		return pipeline.Run{}, notFound(err)
	}
	out := pipeline.Run{
		AgentID: row.AgentID, EnvironmentID: row.EnvironmentID, Active: row.Live, TaskRef: row.TaskRef,
		Principal: principal(row.PrincipalUserID, row.PrincipalSaID, nil),
		Launcher:  principal(row.LauncherUserID, row.LauncherSaID, row.LauncherInstanceID),
	}
	if row.ParentRunID != nil {
		ancestors, err := dbq.New(s.tx).RunAncestors(ctx, org, id)
		if err != nil {
			return pipeline.Run{}, err
		}
		for _, a := range ancestors {
			out.Ancestors = append(out.Ancestors, principal(a.LauncherUserID, a.LauncherSaID, a.LauncherInstanceID),
				principal(a.PrincipalUserID, a.PrincipalSaID, nil))
		}
	}
	if row.InstanceID != nil {
		out.InstanceID = *row.InstanceID
	}
	if row.GrantID != nil {
		if out.GrantID, err = gdomain.ParseGrantID(row.GrantID.String()); err != nil {
			return pipeline.Run{}, err
		}
	}
	return out, nil
}

// Connection implements pipeline.Reader: a connection with its explicit
// route modes (G0 M6) and the reads a verifier can make through it, from
// the package version the org pinned for it (G0 M7; none without a pin).
func (s *snapshot) Connection(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Connection, error) {
	q := dbq.New(s.tx)
	c, err := q.AuthorityConnection(ctx, org, id)
	if err != nil {
		return pipeline.Connection{}, notFound(err)
	}
	routes, err := q.ListConnectionRoutes(ctx, org, id)
	if err != nil {
		return pipeline.Connection{}, err
	}
	out := pipeline.Connection{
		ID: c.ID, Gateway: c.GatewayID, Kind: c.Kind, Package: c.Package, State: c.State, AccessMode: c.AccessMode,
		DefaultMode: c.DefaultMode, DestinationClass: c.DestinationClass, Modes: make(map[string]string, len(routes)),
		Reads: []string{},
	}
	for _, rt := range routes {
		out.Modes[rt.Route] = rt.Mode
	}
	if c.PinnedVersionID != nil {
		p, err := s.r.Definitions.VersionInTx(ctx, s.tx, org, *c.PinnedVersionID)
		if err != nil {
			return pipeline.Connection{}, err
		}
		out.Reads = p.HTTPReads()
	}
	return out, nil
}

func principal(user, sa, instance *ids.UUID) gdomain.Principal {
	switch {
	case user != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: *user}
	case sa != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: *sa}
	case instance != nil:
		return gdomain.Principal{Kind: gdomain.PrincipalInstance, ID: *instance}
	}
	return gdomain.Principal{}
}

// Agent implements pipeline.Reader.
func (s *snapshot) Agent(ctx context.Context, org ids.OrgID, id ids.UUID) (pipeline.Agent, error) {
	a, err := s.r.Grants.AgentInTx(ctx, s.tx, org, id)
	if err != nil {
		return pipeline.Agent{}, notFound(err)
	}
	return pipeline.Agent{State: a.State, BusinessUnitID: a.BusinessUnitID, TeamID: a.TeamID}, nil
}

// Chain implements pipeline.Reader.
func (s *snapshot) Chain(ctx context.Context, org ids.OrgID, id gdomain.GrantID) ([]gdomain.Grant, error) {
	c, err := s.r.Grants.ChainInTx(ctx, s.tx, org, id)
	return c, notFound(err)
}

// Envelopes implements pipeline.Reader.
func (s *snapshot) Envelopes(ctx context.Context, org ids.OrgID, scopes []gdomain.Scope) ([]gdomain.Envelope, error) {
	return s.r.Grants.EnvelopesInTx(ctx, s.tx, org, scopes)
}

// Facts implements pipeline.Reader.
func (s *snapshot) Facts(ctx context.Context, org ids.OrgID, subjectType, subjectID string, names []string) (map[string]fdomain.Fact, error) {
	return s.r.FactStore.Subject(ctx, dbq.New(s.tx), org, subjectType, subjectID, names)
}

// Usage implements pipeline.Reader.
func (s *snapshot) Usage(ctx context.Context, org ids.OrgID, plan gdomain.Plan) (pipeline.Usage, error) {
	acc, ctr, rows, err := pgbudgets.Usage(ctx, dbq.New(s.tx), org, plan.Budgets, plan.Counters)
	out := pipeline.Usage{Accounts: acc, Counters: ctr, CounterRows: rows}
	if out.Accounts == nil {
		out.Accounts = map[bdomain.Ref]bdomain.Account{}
	}
	return out, err
}

// Claim implements pipeline.Reader.
func (s *snapshot) Claim(ctx context.Context, org ids.OrgID, key string) (*pipeline.Claim, error) {
	row, err := dbq.New(s.tx).GetDedupeClaim(ctx, org, key)
	if db.IsNoRows(err) {
		return nil, nil //nolint:nilnil // no earlier attempt
	}
	if err != nil {
		return nil, err
	}
	return &pipeline.Claim{TransactionID: row.TransactionID, State: pipeline.ClaimState(row.State), At: row.ChangedAt}, nil
}

// Lookup implements finalize.Lookuper: the finalization's first lookup, in
// the evaluation's snapshot.
func (s *snapshot) Lookup(ctx context.Context, org ids.OrgID, run, action ids.UUID) (*finalize.Stored, error) {
	return lookup(ctx, dbq.New(s.tx), org, run, action)
}
