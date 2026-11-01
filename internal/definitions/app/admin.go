// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/definitions/trust"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/statemachine"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	tdomain "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Permissions of the package use cases (the tenancy catalog's).
const (
	PermPackageRead     = tdomain.PermPackageRead
	PermPackageImport   = tdomain.PermPackageImport
	PermPackageActivate = tdomain.PermPackageActivate // human only
)

// API errors.
var (
	ErrNotFound          = pcerr.New(pcerr.NotFound, "PACKAGE_NOT_FOUND", "package version or definition not found")
	ErrHumanOnly         = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person can do this")
	ErrRevisionChanged   = pcerr.New(pcerr.Aborted, "PACKAGE_CHANGED", "the package changed meanwhile; read it again")
	errIllegalTransition = pcerr.New(pcerr.FailedPrecondition, "TRANSITION_NOT_ALLOWED", "the package cannot move to that state from its current one")
)

// VersionInfo is one imported package version.
type VersionInfo struct {
	Name, Version string
	State         domain.State
	FileDigest    string
	Definitions   []DefinitionRef
	Pinned        bool
	ImportedAt    time.Time
	// SigningKey is the kid of the org key that signed it; empty when a
	// package root did (HR-162).
	SigningKey string
}

// DefinitionRef names one definition of a version.
type DefinitionRef struct{ Operation, Digest string }

// DefinitionInfo is a stored definition and the newest version holding it.
type DefinitionInfo struct {
	Operation, Digest string
	Canonical         []byte
	Package, Version  string
	State             domain.State
}

// Reads lists what an org imported (the API's view; the pipeline reads
// definitions through its own port).
type Reads interface {
	// ListVersions lists versions, of every package when name is empty.
	ListVersions(ctx context.Context, org ids.OrgID, name string) ([]VersionInfo, error)
	// DefinitionByDigest returns ErrNotFound when the org has no
	// definition with that digest.
	DefinitionByDigest(ctx context.Context, org ids.OrgID, digest string) (DefinitionInfo, error)
}

// Authorizer checks a caller's permission at a path.
type Authorizer interface {
	Require(c tapp.Caller, p tdomain.Permission, path tdomain.Path) error
}

// Admin runs the package use cases of the API: the caller's permission at
// the org, then the Importer. Importing and activating are separate steps,
// and activating is human only (F395).
type Admin struct {
	Importer *Importer
	Reads    Reads
	Authz    Authorizer
	// Ents decides whether the org may use its own package-signing keys
	// (HR-162); without it, org-signed packages are refused.
	Ents Entitlements
	// Protect holds activations for a distinct publisher (G0 M11 D42); nil
	// holds none.
	Protect ActivationGate
	// Checks re-check, in the activating transaction, what was accepted
	// against the definitions active before it: the published policy (G0
	// M4) and the grant and guardrail limits (G0 M8). Any error refuses the
	// activation, which then changes nothing.
	Checks []ActivationCheck
	// Pool runs an activation with Checks in one transaction when Protect
	// is nil. Without it such an activation is refused.
	Pool *db.Pool
	// Catalog refuses to activate a version of a revoked server's package,
	// in the activating transaction (G0 M24 D267).
	Catalog CatalogCheck
}

// CatalogCheck is the MCP catalog's say on activating a package's version.
type CatalogCheck interface {
	CheckPackageActivation(ctx context.Context, tx db.TenantTx, name string) error
}

// ActivationCheck re-checks one thing that depends on the org's active
// definitions when a package version is activated. It runs in the
// activating transaction once the version is ACTIVE there, with the
// active definitions as they are after the activation; an error refuses
// the activation.
type ActivationCheck interface {
	CheckActivation(ctx context.Context, tx db.TenantTx, active []*domain.Definition) error
}

// ActiveDefinitionsTx reads the org's active definitions in tx; a
// Repository needs it to run activation checks.
type ActiveDefinitionsTx interface {
	ActiveDefinitionsInTx(ctx context.Context, tx db.TenantTx, org ids.OrgID) ([]*domain.Definition, error)
}

// apiError maps import and lifecycle errors to API errors. The messages
// describe the request (signatures, digests, versions), never another
// org's data.
func apiError(err error) error {
	for _, m := range []struct {
		sentinel error
		code     pcerr.Code
		name     string
	}{
		{trust.ErrExpired, pcerr.FailedPrecondition, "PACKAGE_METADATA_EXPIRED"},
		{trust.ErrRollback, pcerr.FailedPrecondition, "PACKAGE_METADATA_ROLLBACK"},
		{trust.ErrUntrusted, pcerr.FailedPrecondition, "PACKAGE_UNTRUSTED"},
		{domain.ErrPinRollback, pcerr.FailedPrecondition, "PACKAGE_PIN_ROLLBACK"},
		{domain.ErrPinConflict, pcerr.FailedPrecondition, "PACKAGE_PIN_CONFLICT"},
		{ErrOperationTaken, pcerr.FailedPrecondition, "PACKAGE_OPERATION_TAKEN"},
		{ErrKeyCompromised, pcerr.FailedPrecondition, "PACKAGE_KEY_COMPROMISED"},
		{manifest.ErrInvalid, pcerr.InvalidArgument, "PACKAGE_INVALID"},
		{domain.ErrInvalid, pcerr.InvalidArgument, "PACKAGE_INVALID"},
	} {
		if errors.Is(err, m.sentinel) {
			return pcerr.Wrap(err, m.code, m.name, strings.TrimPrefix(err.Error(), m.sentinel.Error()+": "))
		}
	}
	switch {
	case errors.Is(err, ErrConflict):
		return ErrRevisionChanged
	case errors.Is(err, statemachine.ErrIllegalTransition):
		return errIllegalTransition
	}
	return err
}

func (a *Admin) caller(ctx context.Context, p tdomain.Permission) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return tapp.Caller{}, err
	}
	return c, a.Authz.Require(c, p, tdomain.OrgPath(c.Org))
}

// Import verifies and stores one package version (package.import at the
// org). It starts REVIEWED and decides nothing until activated.
func (a *Admin) Import(ctx context.Context, name, version, targets string, raw []byte) (VersionInfo, bool, error) {
	c, err := a.caller(ctx, PermPackageImport)
	if err != nil {
		return VersionInfo{}, false, err
	}
	// Only routing: the importer verifies an org kid against the org's
	// keys alone, so a forged kid cannot skip this check.
	if kid, _, err := jws.Unverified(strings.TrimSpace(targets)); err == nil && trust.IsOrgKID(kid) {
		if err := a.entitled(ctx); err != nil {
			return VersionInfo{}, false, err
		}
	}
	ev := &audit.Event{
		Name: "package.imported", Actor: c.Actor(), Outcome: audit.Success,
		Object: &audit.Object{Type: "package_version", ID: trust.Key(name, version)},
	}
	res, err := a.Importer.Import(ctx, c.Org, name, version, targets, raw, ev)
	if err != nil {
		return VersionInfo{}, false, apiError(err)
	}
	v, err := a.version(ctx, c.Org, name, version)
	return v, res.Unchanged, err
}

// Transition moves a package version through its lifecycle
// (package.activate at the org, human only). Quarantining or retiring one
// invalidates permits already issued (the repository raises the epoch).
func (a *Admin) Transition(ctx context.Context, name, version string, to domain.State) (VersionInfo, error) {
	c, err := a.caller(ctx, PermPackageActivate)
	if err != nil {
		return VersionInfo{}, err
	}
	if !c.Human() {
		return VersionInfo{}, ErrHumanOnly
	}
	if to == domain.StateActive && a.Protect != nil {
		// G0 M11 D42: activating a version changes what tools mean and what
		// their consequences are, so with TOOL_MEANING or CONSEQUENCE_RULES
		// protected it waits for a distinct publisher.
		if err := a.Protect.Activate(ctx, c, name, version, func(ctx context.Context, tx db.TenantTx) error {
			return a.activateTx(ctx, tx, c, name, version)
		}); err != nil {
			return VersionInfo{}, apiError(notFound(err))
		}
		return a.version(ctx, c.Org, name, version)
	}
	if to == domain.StateActive && (len(a.Checks) > 0 || a.Catalog != nil) {
		if a.Pool == nil {
			return VersionInfo{}, errNoActivationChecks
		}
		if err := a.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
			return a.activateTx(ctx, tx, c, name, version)
		}); err != nil {
			return VersionInfo{}, apiError(notFound(err))
		}
		return a.version(ctx, c.Org, name, version)
	}
	from, err := a.Importer.Repo.State(ctx, c.Org, name, version)
	if err != nil {
		return VersionInfo{}, notFound(err)
	}
	ev := &audit.Event{
		Name: "package.transitioned", Actor: c.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "package_version", ID: trust.Key(name, version)},
		Details: map[string]string{"from": string(from), "to": string(to)},
	}
	if err := a.Importer.Transition(ctx, c.Org, name, version, to, ev); err != nil {
		return VersionInfo{}, apiError(notFound(err))
	}
	return a.version(ctx, c.Org, name, version)
}

// ActivationGate holds package activations for a distinct publisher (G0
// M11 D42; the server's protect.Gate): activate runs in its transaction
// unless the org protects TOOL_MEANING or CONSEQUENCE_RULES, when the
// activation is stored and protect.ErrPending returned instead.
type ActivationGate interface {
	Activate(ctx context.Context, author tapp.Caller, name, version string, activate func(context.Context, db.TenantTx) error) error
}

// TxRepository is the part of the Repository a protected activation uses
// in the confirming transaction.
type TxRepository interface {
	StateTx(ctx context.Context, tx db.TenantTx, pkg, version string) (domain.State, error)
	TransitionTx(ctx context.Context, tx db.TenantTx, pkg, version string, from, to domain.State, ev *audit.Event) error
}

// ActivationInput is an activation, as a protected change stores it.
type ActivationInput struct{ Name, Version string }

// ApplyProtectedActivation re-runs a confirmed protected activation as its
// author (a protect.Applier): they must still hold package.activate.
func (a *Admin) ApplyProtectedActivation(ctx context.Context, tx db.TenantTx, author tapp.Caller, payload []byte) error {
	var in ActivationInput
	if err := json.Unmarshal(payload, &in); err != nil || in.Name == "" || in.Version == "" {
		return ErrNotFound
	}
	if err := a.Authz.Require(author, PermPackageActivate, tdomain.OrgPath(author.Org)); err != nil {
		return err
	}
	if !author.Human() {
		return ErrHumanOnly
	}
	return apiError(notFound(a.activateTx(ctx, tx, author, in.Name, in.Version)))
}

// activateTx is Importer.Transition to ACTIVE in tx.
func (a *Admin) activateTx(ctx context.Context, tx db.TenantTx, c tapp.Caller, name, version string) error {
	repo, ok := a.Importer.Repo.(TxRepository)
	if !ok {
		return errNoTxRepository
	}
	from, err := repo.StateTx(ctx, tx, name, version)
	if err != nil {
		return err
	}
	if err := domain.Lifecycle.Check(from, domain.StateActive); err != nil {
		return err
	}
	if a.Catalog != nil {
		if err := a.Catalog.CheckPackageActivation(ctx, tx, name); err != nil {
			return err
		}
	}
	if a.Importer.Keys != nil {
		k, err := a.Importer.Keys.VersionSigner(ctx, c.Org, name, version)
		if err != nil {
			return err
		}
		if k != nil && k.Reason == RevokeCompromised {
			return ErrKeyCompromised
		}
	}
	ev := &audit.Event{
		Name: "package.transitioned", Actor: c.Actor(), Outcome: audit.Success,
		Object:  &audit.Object{Type: "package_version", ID: trust.Key(name, version)},
		Details: map[string]string{"from": string(from), "to": string(domain.StateActive)},
	}
	err = repo.TransitionTx(ctx, tx, name, version, from, domain.StateActive, ev)
	if errors.Is(err, db.ErrLostRace) {
		return ErrConflict
	}
	if err != nil || len(a.Checks) == 0 {
		return err
	}
	// Fail closed at activation, not only at decision time: the version is
	// ACTIVE in tx, so the checks see the definitions as they will be.
	reads, ok := a.Importer.Repo.(ActiveDefinitionsTx)
	if !ok {
		return errNoActivationChecks
	}
	active, err := reads.ActiveDefinitionsInTx(ctx, tx, c.Org)
	if err != nil {
		return err
	}
	for _, check := range a.Checks {
		if err := check.CheckActivation(ctx, tx, active); err != nil {
			return err
		}
	}
	return nil
}

var errNoActivationChecks = pcerr.New(pcerr.Unavailable, "PACKAGE_CHECKS_UNAVAILABLE", "package activation checks are not available on this server")

var errNoTxRepository = pcerr.New(pcerr.Unavailable, "PROTECTED_CHANGES_UNAVAILABLE", "protected package activation is not available on this server")

// List lists imported package versions (package.read at the org).
func (a *Admin) List(ctx context.Context, name string) ([]VersionInfo, error) {
	c, err := a.caller(ctx, PermPackageRead)
	if err != nil {
		return nil, err
	}
	return a.Reads.ListVersions(ctx, c.Org, name)
}

// Definition returns one definition by digest (package.read at the org).
func (a *Admin) Definition(ctx context.Context, digest string) (DefinitionInfo, error) {
	c, err := a.caller(ctx, PermPackageRead)
	if err != nil {
		return DefinitionInfo{}, err
	}
	d, err := a.Reads.DefinitionByDigest(ctx, c.Org, digest)
	return d, notFound(err)
}

func (a *Admin) version(ctx context.Context, org ids.OrgID, name, version string) (VersionInfo, error) {
	vs, err := a.Reads.ListVersions(ctx, org, name)
	if err != nil {
		return VersionInfo{}, err
	}
	for _, v := range vs {
		if v.Version == version {
			return v, nil
		}
	}
	return VersionInfo{}, ErrNotFound
}

func notFound(err error) error {
	if errors.Is(err, ErrMissing) {
		return ErrNotFound
	}
	return err
}

// ProtectedActivationState is the state a protected activation's re-run
// must still find (a protect.State): the version's lifecycle state.
func (a *Admin) ProtectedActivationState(ctx context.Context, tx db.TenantTx, payload []byte) ([]byte, error) {
	var in ActivationInput
	if err := json.Unmarshal(payload, &in); err != nil {
		return nil, ErrNotFound
	}
	repo, ok := a.Importer.Repo.(TxRepository)
	if !ok {
		return nil, errNoTxRepository
	}
	st, err := repo.StateTx(ctx, tx, in.Name, in.Version)
	if errors.Is(err, ErrMissing) {
		return []byte("none"), nil
	} else if err != nil {
		return nil, err
	}
	return []byte(st), nil
}
