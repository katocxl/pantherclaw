// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app installs PantherClaw Hub items (G0 M23 D103–D105; HR-560–HR-563).
//
// The server verifies everything itself: pclaw is only the transport, and the
// server never fetches anything (D107). An install is always inert (HR-561):
// an item becomes a draft through its kind's own use case, with that use
// case's permission and edition, and nothing here activates, publishes or
// enables anything. Those use cases run in their own transactions, so an
// install is recorded PENDING first, with the index it came from, and ended
// INSTALLED or FAILED afterwards.
package app

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/hub/domain"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// API errors (D105).
var (
	ErrHumanOnly  = pcerr.New(pcerr.PermissionDenied, "HUMAN_ONLY", "only a person signed in as themselves can install from Hub")
	ErrLocalOnly  = pcerr.New(pcerr.FailedPrecondition, "KIND_LOCAL_ONLY", "a range scenario is never installed on a server: pclaw hub install writes it locally")
	ErrBusy       = pcerr.New(pcerr.Aborted, "HUB_INSTALL_BUSY", "this item is being installed; try again shortly")
	errEnvMissing = pcerr.New(pcerr.InvalidArgument, "HUB_ENVIRONMENT", "no single active environment has that slug")
)

// Status is an install's state.
type Status string

// The statuses.
const (
	StatusPending   Status = "PENDING"
	StatusInstalled Status = "INSTALLED"
	StatusFailed    Status = "FAILED"
)

// The kinds of thing an install makes.
const (
	ResultPolicyVersion  = "policy_version"
	ResultCustomRule     = "custom_rule"
	ResultAutomation     = "automation"
	ResultPackageVersion = "package_version"
)

// Install is one installed item.
type Install struct {
	ID            ids.UUID
	Name, Version string
	Kind          domain.Kind
	ItemSHA256    string
	IndexVersion  uint64
	ResultKind    string
	ResultRef     string
	InstalledBy   string
	InstalledAt   time.Time
	Status        Status
	// Claim names the worker holding a PENDING install; only it can finish
	// the install (D130).
	Claim ids.UUID
	// Reclaimed: Begin took over a FAILED or abandoned install, so its draft
	// may exist already. Set by Begin only.
	Reclaimed bool
}

// Begin is what recording an install needs.
type Begin struct {
	Index       domain.Verified
	Entry       domain.Entry
	InstalledBy string
}

// Finish ends an install.
type Finish struct {
	ID         ids.UUID
	Claim      ids.UUID
	Status     Status
	ResultKind string
	ResultRef  string
	// Replaced are the ids the draft changes; their count is audited.
	Replaced []string
}

// State is the highest index an org accepted.
type State struct {
	domain.State
	UpdatedAt time.Time
}

// Store persists installs and the org's index state.
type Store interface {
	// State returns the org's state, nil if it accepted no index.
	State(ctx context.Context, org ids.OrgID) (*State, error)
	// Begin, in one transaction serialized per org, refuses an index
	// domain.CheckAdvance refuses and advances the state. Then it records the
	// install: a new one PENDING, a FAILED or abandoned one PENDING again.
	// With the same digest already INSTALLED it returns that install and
	// true. Another digest under the same name and version is
	// domain.ErrDigest, and one still in progress ErrBusy.
	Begin(ctx context.Context, org ids.OrgID, c tapp.Caller, b Begin) (Install, bool, error)
	// Finish ends a PENDING install still holding f.Claim and audits it, in
	// one transaction. A row another worker reclaimed is ErrBusy.
	Finish(ctx context.Context, org ids.OrgID, c tapp.Caller, f Finish) (Install, error)
	// List returns installs newest first, before an id when one is given.
	List(ctx context.Context, org ids.OrgID, limit int, before *ids.UUID) ([]Install, error)
	// EnvironmentID returns the one active environment with a slug.
	EnvironmentID(ctx context.Context, org ids.OrgID, slug string) (ids.UUID, error)
}

// ErrNoEnvironment is Store.EnvironmentID's error.
var ErrNoEnvironment = errors.New("hub: no single environment has that slug")

// Service runs the Hub use cases.
type Service struct {
	Store Store
	// Roots are what the index is verified with: the embedded Hub roots and,
	// on a server that is local only, the development Hub key (D101).
	Roots domain.Roots
	Clock clock.Clock
	// One port per kind; each checks its own permission and edition.
	Policies    PolicyDrafts
	Detections  DetectionDrafts
	Automations AutomationDrafts
	Packages    PackageImports
}

// Input is an install request.
type Input struct {
	IndexJWS string
	Item     []byte
	Params   map[string]string
}

// Installed is the result of an install.
type Installed struct {
	Install Install
	// Already: this digest was installed before; nothing changed.
	Already bool
	// Skipped are per-agent rules a policy template left out.
	Skipped []string
	// Replaced are the rule and test ids of the published policy the draft
	// changes (D135).
	Replaced []string
}

// verifyError maps the verification errors to their stable codes (D105). The
// messages describe the request, never another org's data.
func verifyError(err error) error {
	for _, m := range []struct {
		sentinel error
		code     pcerr.Code
		reason   string
	}{
		{domain.ErrNoRoot, pcerr.FailedPrecondition, "HUB_NO_ROOT"},
		{domain.ErrExpired, pcerr.FailedPrecondition, "HUB_EXPIRED"},
		{domain.ErrRollback, pcerr.FailedPrecondition, "HUB_ROLLBACK"},
		{domain.ErrSignature, pcerr.FailedPrecondition, "HUB_SIGNATURE"},
		{domain.ErrDigest, pcerr.FailedPrecondition, "HUB_DIGEST"},
		{domain.ErrItem, pcerr.InvalidArgument, "HUB_ITEM_INVALID"},
	} {
		if errors.Is(err, m.sentinel) {
			return pcerr.Wrap(err, m.code, m.reason, strings.TrimPrefix(err.Error(), m.sentinel.Error()+": "))
		}
	}
	if errors.Is(err, ErrNoEnvironment) {
		return errEnvMissing
	}
	return err
}

// Install verifies the index and the item, and installs the item as an inert
// draft (hub.install at the org; a person only).
func (s *Service) Install(ctx context.Context, in Input) (Installed, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return Installed{}, err
	}
	if err := c.Require(td.PermHubInstall, td.OrgPath(c.Org)); err != nil {
		return Installed{}, err
	}
	if !c.Human() || c.Credential == tapp.CredAPIKey {
		return Installed{}, ErrHumanOnly
	}
	v, err := domain.Verify(in.IndexJWS, s.Roots, s.Clock.Now())
	if err != nil {
		return Installed{}, verifyError(err)
	}
	e, it, err := v.Match(in.Item)
	if err != nil {
		return Installed{}, verifyError(err)
	}
	if it.Kind == domain.KindRangeScenario {
		return Installed{}, ErrLocalOnly
	}
	// What can be refused without writing is refused before the install is
	// recorded.
	d, err := s.prepare(ctx, c, e, it, in.Params)
	if err != nil {
		return Installed{}, verifyError(err)
	}
	rec, already, err := s.Store.Begin(ctx, c.Org, c, Begin{Index: v, Entry: e, InstalledBy: c.Principal.String()})
	if err != nil {
		return Installed{}, verifyError(err)
	}
	if already {
		return Installed{Install: rec, Already: true}, nil
	}
	// A crash can fall between the draft's commit and Finish: a retry finds
	// that draft rather than making another (D130). What it can't find, it
	// makes, and a refusal there leaves the install FAILED with its reason.
	var res result
	found := false
	var runErr error
	if rec.Reclaimed && d.find != nil {
		res, found, runErr = d.find(ctx)
	}
	if runErr == nil && !found {
		res, runErr = d.create(ctx)
	}
	// Recording the end outlives a caller that went away.
	end := context.WithoutCancel(ctx)
	if runErr != nil {
		if _, err := s.Store.Finish(end, c.Org, c, Finish{ID: rec.ID, Claim: rec.Claim, Status: StatusFailed}); err != nil {
			return Installed{}, errors.Join(runErr, fmt.Errorf("hub: recording the failed install: %w", err))
		}
		return Installed{}, runErr
	}
	done, err := s.Store.Finish(end, c.Org, c, Finish{
		ID: rec.ID, Claim: rec.Claim, Status: StatusInstalled, ResultKind: res.kind, ResultRef: res.ref, Replaced: res.replaced,
	})
	if err != nil {
		return Installed{}, err
	}
	return Installed{Install: done, Skipped: res.skipped, Replaced: res.replaced}, nil
}

func reader(ctx context.Context) (tapp.Caller, error) {
	c, err := tapp.CallerFrom(ctx)
	if err != nil {
		return c, err
	}
	return c, c.Require(td.PermHubRead, td.OrgPath(c.Org))
}

// List lists the org's installs, newest first (hub.read at the org).
func (s *Service) List(ctx context.Context, limit int, before *ids.UUID) ([]Install, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	return s.Store.List(ctx, c.Org, limit, before)
}

// State returns the highest index the org accepted, nil if none (hub.read at
// the org).
func (s *Service) State(ctx context.Context) (*State, error) {
	c, err := reader(ctx)
	if err != nil {
		return nil, err
	}
	return s.Store.State(ctx, c.Org)
}
