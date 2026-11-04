// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves the threat map (G0 M28 D710, D713, D719-D724): it
// checks the caller's permission, credential, edition and scope, reads the
// org's records through ports and evaluates them with the pure domain. A
// lane is what PantherClaw's own records show; nothing here writes but the
// snapshot job.
package app

import (
	"context"
	"errors"
	"time"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/catalog"
	"github.com/katocxl/pantherclaw/internal/threatmap/domain"
	"github.com/katocxl/pantherclaw/internal/threatmap/mapset"
	"github.com/katocxl/pantherclaw/internal/threatmap/navigator"
	"github.com/katocxl/pantherclaw/internal/threatmap/ports"
	txapp "github.com/katocxl/pantherclaw/internal/transactions/app"
)

// API errors of the service (D721, D723).
var (
	// ErrAPIEdition: the four reads with an API key or access token need
	// Team (founder FQ1 A). The message is the one D723 fixes.
	ErrAPIEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"Reading the threat map with an API key or access token needs Team or higher; the console shows it on every edition.")
	// ErrExportEdition: the Navigator layer and the pack need Team.
	ErrExportEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"Exporting the threat map needs Team or higher.")
	// ErrHistoryEdition: the history needs Business.
	ErrHistoryEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"The threat map history needs Business or higher.")
	// ErrUnknownTechnique: not a technique of the framework's catalog, or
	// a deprecated or revoked one.
	ErrUnknownTechnique = pcerr.New(pcerr.InvalidArgument, "UNKNOWN_TECHNIQUE",
		"not a current technique of this framework's catalog")
	// ErrNavigatorNotAvailable: MITRE publishes no Navigator domain for the
	// pinned ATLAS catalog (D720).
	ErrNavigatorNotAvailable = pcerr.New(pcerr.FailedPrecondition, "NAVIGATOR_NOT_AVAILABLE",
		"MITRE publishes no ATT&CK Navigator domain for the pinned ATLAS catalog; export ATT&CK Enterprise, or use the signed pack.")
	// ErrNotFound answers for an agent or environment outside the caller's
	// scope as for one that does not exist.
	ErrNotFound = pcerr.New(pcerr.NotFound, "NOT_FOUND", "no such record")
	// ErrNoEditions is a wiring error.
	ErrNoEditions = errors.New("threatmap: no entitlements source")
)

// HistoryDays bounds a history read; snapshots older than it are deleted.
const HistoryDays = 400

// Entitlements reads the caller's org's licence.
type Entitlements interface {
	Current(ctx context.Context) (billing.Entitlements, error)
}

// Service serves ThreatMapService.
type Service struct {
	Pool  *db.Pool
	Ents  Entitlements
	Store ports.Store
	// Now overrides the clock; tests set it.
	Now func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Scope is a read's filter: an agent or an environment, or neither.
type Scope struct {
	Agent       ids.UUID
	Environment ids.UUID
}

func (sc Scope) domain() domain.Scope {
	var out domain.Scope
	if !sc.Agent.IsZero() {
		out.AgentID = sc.Agent.String()
	}
	if !sc.Environment.IsZero() {
		out.EnvironmentID = sc.Environment.String()
	}
	return out
}

// gate is what a read needs beyond threatmap.read.
type gate int

const (
	gateRead gate = iota
	gateExport
	gateHistory
)

// editions checks the permission anywhere, then the edition the read needs.
// The four reads let a person signed in to the console read on every
// edition; any other credential needs ThreatMapAPIReads (FQ1 A: deny by
// default). The credential is the server's own caller, never a request
// field.
func (s *Service) editions(ctx context.Context, g gate) (tenancy.Caller, billing.Entitlements, error) {
	c, err := tenancy.CallerFrom(ctx)
	if err != nil {
		return c, billing.Entitlements{}, err
	}
	if !c.CanAnywhere(td.PermThreatMapRead) {
		return c, billing.Entitlements{}, td.ErrPermissionDenied(td.PermThreatMapRead)
	}
	if s.Ents == nil {
		return c, billing.Entitlements{}, ErrNoEditions
	}
	e, err := s.Ents.Current(ctx)
	if err != nil {
		return c, e, err
	}
	switch g {
	case gateRead:
		// A console session reads on every edition; any other credential
		// (an API key, an access token, or one added later) needs the
		// edition: deny by default (FQ1).
		console := c.Credential == tenancy.CredBrowserSession || c.Credential == tenancy.CredSupportSession
		if !console && !e.ThreatMapAPIReads() {
			return c, e, ErrAPIEdition
		}
	case gateExport:
		if !e.ThreatMapExport() {
			return c, e, ErrExportEdition
		}
	case gateHistory:
		if !e.ThreatMapHistory() {
			return c, e, ErrHistoryEdition
		}
	}
	return c, e, nil
}

// inScope checks the filter against the caller's scope (D722): no filter
// needs threatmap.read at the org; an agent or environment the caller may
// not read answers NotFound, like one that does not exist.
func (s *Service) inScope(ctx context.Context, tx db.TenantTx, c tenancy.Caller, sc Scope) error {
	switch {
	case !sc.Agent.IsZero():
		ok, err := txapp.NewAgentScope(c, dbq.New(tx), td.PermThreatMapRead).Can(ctx, sc.Agent)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		if !ok {
			return ErrNotFound
		}
	case !sc.Environment.IsZero():
		p, ok, err := s.Store.EnvironmentPath(ctx, tx, c.Org, sc.Environment)
		if err != nil {
			return err
		}
		if !ok || !c.Can(td.PermThreatMapRead, p) {
			return ErrNotFound
		}
	default:
		if !c.Can(td.PermThreatMapRead, td.OrgPath(c.Org)) {
			return td.ErrPermissionDenied(td.PermThreatMapRead)
		}
	}
	return nil
}

// EditionsOf is what the evaluator reads of the licence.
func EditionsOf(e billing.Entitlements) domain.Editions {
	return domain.Editions{
		AdvancedDetections: e.AdvancedDetections(), CustomDetections: e.CustomDetections(),
		BehaviorAnalytics: e.BehaviorAnalytics(), ContentSignals: e.ContentSignals(),
		Automations: e.Automations(), AutomationPlaybooks: e.AutomationPlaybooks(),
	}
}

// Gather reads every input of one evaluation in tx (D720: a pack carries
// them all).
func Gather(ctx context.Context, store ports.Store, tx db.TenantTx, org ids.OrgID, f catalog.Framework, sc domain.Scope,
	e billing.Entitlements, now time.Time,
) (domain.Inputs, error) {
	rec, err := store.Records(ctx, tx, org, now)
	if err != nil {
		return domain.Inputs{}, err
	}
	return inputsFor(ctx, store, tx, org, rec, f, sc, e, now)
}

// inputsFor completes the org's records into one scope's inputs.
func inputsFor(ctx context.Context, store ports.Store, tx db.TenantTx, org ids.OrgID, rec ports.Records, f catalog.Framework,
	sc domain.Scope, e billing.Entitlements, now time.Time,
) (domain.Inputs, error) {
	in := domain.Inputs{Framework: f, Scope: sc, EvaluatedAt: now, Editions: EditionsOf(e)}
	in.ContentMode, in.MCPCatalogEnforcing = rec.ContentMode, rec.MCPCatalogEnforcing
	in.Agents, in.Routes, in.Rules, in.Cursor = rec.Agents, rec.Routes, rec.Rules, rec.Cursor
	in.Automations, in.Results = rec.Automations, rec.Results
	all, agents := true, []ids.UUID{}
	if sc.AgentID != "" || sc.EnvironmentID != "" {
		all = false
		for _, a := range rec.Agents {
			if (sc.AgentID != "" && a.ID == sc.AgentID) || (sc.EnvironmentID != "" && a.EnvironmentID == sc.EnvironmentID) {
				id, err := ids.ParseUUID(a.ID)
				if err != nil {
					return in, err
				}
				agents = append(agents, id)
			}
		}
	}
	seen, err := store.Seen(ctx, tx, org, now.Add(-time.Duration(domain.SeenDays)*24*time.Hour), all, agents)
	if err != nil {
		return in, err
	}
	in.Alerts, in.Decisions = seen.Alerts, seen.Decisions
	return in, nil
}

// evaluate reads and evaluates one framework for the caller.
func (s *Service) evaluate(ctx context.Context, g gate, f catalog.Framework, sc Scope) (domain.Map, error) {
	c, e, err := s.editions(ctx, g)
	if err != nil {
		return domain.Map{}, err
	}
	return s.evaluateAs(ctx, c, e, f, sc)
}

// evaluateAs evaluates for a caller whose permission and edition are
// checked.
func (s *Service) evaluateAs(ctx context.Context, c tenancy.Caller, e billing.Entitlements, f catalog.Framework, sc Scope) (domain.Map, error) {
	m, _, _, err := s.evaluateWith(ctx, c, e, f, sc)
	return m, err
}

// evaluateWith evaluates and also returns the inputs and the mapping it
// read, which a pack carries (D720).
func (s *Service) evaluateWith(ctx context.Context, c tenancy.Caller, e billing.Entitlements, f catalog.Framework, sc Scope,
) (domain.Map, domain.Inputs, domain.Mapping, error) {
	now := s.now()
	var err error
	var in domain.Inputs
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		if err := s.inScope(ctx, tx, c, sc); err != nil {
			return err
		}
		in, err = Gather(ctx, s.Store, tx, c.Org, f, sc.domain(), e, now)
		return err
	}, db.ReadOnly(), db.RepeatableRead())
	if err != nil {
		return domain.Map{}, domain.Inputs{}, domain.Mapping{}, err
	}
	mp := mapset.Evaluator(f)
	return domain.Evaluate(catalog.Load(f), mp, in), in, mp, nil
}

// CheckPackScope checks a threat map pack's scope when it is created (G0
// M28 D720a): threatmap.read at org scope without an environment, or on an
// environment of the org, which is otherwise NotFound.
func (s *Service) CheckPackScope(ctx context.Context, tx db.TenantTx, c tenancy.Caller, env ids.UUID) error {
	return s.inScope(ctx, tx, c, Scope{Environment: env})
}

// PackReport evaluates the report a threat map pack holds, as the pack's
// creator in ctx when the pack is built (D720): Team or higher, and
// threatmap.read on the scope then.
func (s *Service) PackReport(ctx context.Context, f catalog.Framework, env ids.UUID) (domain.Report, error) {
	c, e, err := s.editions(ctx, gateExport)
	if err != nil {
		return domain.Report{}, err
	}
	m, in, mp, err := s.evaluateWith(ctx, c, e, f, Scope{Environment: env})
	if err != nil {
		return domain.Report{}, err
	}
	return domain.NewReport(c.Org.String(), m, in, mp), nil
}

// FrameworkInfo is one framework's catalog.
type FrameworkInfo struct {
	Framework      catalog.Framework
	Title          string
	CatalogVersion string
	CatalogDigest  string
	Techniques     int
	Tactics        int
}

// Titles of the frameworks.
var titles = map[catalog.Framework]string{
	catalog.FrameworkATLAS:  "MITRE ATLAS",
	catalog.FrameworkATTACK: "MITRE ATT&CK Enterprise",
}

// Frameworks lists the pinned catalogs.
func (s *Service) Frameworks(ctx context.Context) ([]FrameworkInfo, error) {
	if _, _, err := s.editions(ctx, gateRead); err != nil {
		return nil, err
	}
	out := make([]FrameworkInfo, 0, len(catalog.Frameworks()))
	for _, f := range catalog.Frameworks() {
		cat := catalog.Load(f)
		out = append(out, FrameworkInfo{
			Framework: f, Title: titles[f], CatalogVersion: cat.Version, CatalogDigest: cat.Digest,
			Techniques: len(cat.Matrix()), Tactics: len(cat.Tactics),
		})
	}
	return out, nil
}

// Matrix evaluates a framework's matrix for the scope.
func (s *Service) Matrix(ctx context.Context, f catalog.Framework, sc Scope) (domain.Map, error) {
	return s.evaluate(ctx, gateRead, f, sc)
}

// Technique evaluates one technique, or sub-technique, and its page.
func (s *Service) Technique(ctx context.Context, f catalog.Framework, id string, sc Scope) (domain.Map, domain.Technique, error) {
	c, e, err := s.editions(ctx, gateRead)
	if err != nil {
		return domain.Map{}, domain.Technique{}, err
	}
	if !catalog.Load(f).Active(id) {
		return domain.Map{}, domain.Technique{}, ErrUnknownTechnique
	}
	m, err := s.evaluateAs(ctx, c, e, f, sc)
	if err != nil {
		return m, domain.Technique{}, err
	}
	t, ok := m.Technique(id)
	if !ok {
		return m, t, ErrUnknownTechnique
	}
	return m, t, nil
}

// Gaps lists the scope's gaps, grouped by fix target, then technique.
func (s *Service) Gaps(ctx context.Context, f catalog.Framework, sc Scope) (domain.Map, []domain.Gap, error) {
	m, err := s.evaluate(ctx, gateRead, f, sc)
	if err != nil {
		return m, nil, err
	}
	return m, m.Gaps(), nil
}

// Navigator writes the scope's Navigator layer (Team, D720).
func (s *Service) Navigator(ctx context.Context, f catalog.Framework, sc Scope) ([]byte, string, error) {
	if f != catalog.FrameworkATTACK {
		if _, _, err := s.editions(ctx, gateExport); err != nil {
			return nil, "", err
		}
		return nil, "", ErrNavigatorNotAvailable
	}
	m, err := s.evaluate(ctx, gateExport, f, sc)
	if err != nil {
		return nil, "", err
	}
	b, name, err := navigator.JSON(m)
	if errors.Is(err, navigator.ErrNotAvailable) {
		return nil, "", ErrNavigatorNotAvailable
	}
	return b, name, err
}
