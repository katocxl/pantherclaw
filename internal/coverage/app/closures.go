// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves coverage's use cases (G0 M9 track A): recording the
// sandbox's closure evidence and other invalidating changes, the route
// inventory, and the reads of CoverageService.
package app

import (
	"context"
	"encoding/json/v2"
	"regexp"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Errors of the coverage use cases.
var (
	ErrNotFound       = pcerr.New(pcerr.NotFound, "COVERAGE_NOT_FOUND", "not found")
	ErrClosure        = pcerr.New(pcerr.InvalidArgument, "INVALID_CLOSURE", "closure evidence needs 1 to 128 probe results with known roles and outcomes, a key thumbprint, a server nonce, a runc or runsc engine, 1 to 16 image digests and times within the last hour")
	ErrClosureStale   = pcerr.New(pcerr.FailedPrecondition, "CLOSURE_STALE", "the scope changed during the sandbox session; run it again")
	ErrNoBinding      = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_UNBOUND", "the connection is retired or its package has no pinned version")
	ErrInvalidation   = pcerr.New(pcerr.InvalidArgument, "INVALID_INVALIDATION", "unknown invalidation kind or a detail longer than 200 characters")
	jktPattern        = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	noncePattern      = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	digestPattern     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	enginePattern     = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	apiVersionPattern = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}$`)
)

// Service serves coverage as pc_app.
type Service struct {
	Pool      *db.Pool
	Freshness domain.Freshness
	// Clock checks closure times; nil is the wall clock.
	Clock clock.Clock
}

func (s *Service) now() time.Time {
	if s.Clock == nil {
		return time.Now()
	}
	return s.Clock.Now()
}

func validClosure(c domain.Closure, now time.Time) bool {
	roles := []string{domain.RoleProbe, domain.RolePositiveControl, domain.RoleNegativeControl, domain.RoleCanary}
	outcomes := []string{domain.Blocked, domain.Reachable}
	if len(c.Probes) == 0 || len(c.Probes) > 128 {
		return false
	}
	for _, p := range c.Probes {
		if p.Name == "" || len(p.Name) > 64 || !slices.Contains(roles, p.Role) || !slices.Contains(outcomes, p.Expect) ||
			!slices.Contains(append(outcomes, domain.ProbeErr), p.Observed) || len(p.Detail) > 512 {
			return false
		}
	}
	if len(c.ImageDigests) == 0 || len(c.ImageDigests) > 16 ||
		slices.ContainsFunc(c.ImageDigests, func(d string) bool { return !digestPattern.MatchString(d) }) {
		return false
	}
	return jktPattern.MatchString(c.SigningKeyJKT) && noncePattern.MatchString(c.ServerNonce) &&
		enginePattern.MatchString(c.Engine.Version) && apiVersionPattern.MatchString(c.Engine.APIVersion) &&
		(c.Engine.Runtime == "runc" || c.Engine.Runtime == "runsc") && !c.Agent.IsZero() && !c.Connection.IsZero() &&
		!c.SandboxSession.IsZero() && !c.Bound.Gateway.IsZero() && !c.SessionStartedAt.After(c.ObservedAt) &&
		!c.ObservedAt.After(now.Add(time.Minute)) && c.ObservedAt.After(now.Add(-time.Hour))
}

// RecordClosure stores the closure evidence of one sandbox session for one
// agent and connection, in the caller's transaction. Only the sandbox
// module calls it, after it verified the signature over the results and
// their server nonce (HR-215); no RPC reaches it otherwise. Coverage
// decides itself whether the closure passed (domain.Evaluate), binds it to
// the connection's current revision, gateway and package version, and
// gives it the freshness contract's expiry (HR-211). A closure whose scope
// changed after the session started is refused; a failed one is stored
// and drops any ENFORCED state of the scope at once.
func (s *Service) RecordClosure(ctx context.Context, tx db.TenantTx, c domain.Closure) (ids.UUID, error) {
	now := s.now()
	if !validClosure(c, now) {
		return ids.UUID{}, ErrClosure
	}
	q := dbq.New(tx)
	b, err := q.CoverageBinding(ctx, tx.OrgID(), c.Connection)
	if db.IsNoRows(err) || (err == nil && b.State == "RETIRED") {
		return ids.UUID{}, ErrNoBinding
	} else if err != nil {
		return ids.UUID{}, err
	}
	changes, err := q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
		OrgID: tx.OrgID(), ConnectionID: c.Connection, AgentID: &c.Agent, Since: c.SessionStartedAt,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	if slices.ContainsFunc(changes, func(ch dbq.PcCoverageInvalidation) bool {
		return domain.InvalidationKind(ch.Kind).Invalidates()
	}) {
		return ids.UUID{}, ErrClosureStale
	}
	v := domain.Evaluate(c.Probes, c.ConfigChecks)
	probes, err := json.Marshal(c.Probes)
	if err != nil {
		return ids.UUID{}, err
	}
	result := "FAILED"
	if v.Passed {
		result = "PASSED"
	}
	row, err := q.InsertCoverageClosure(ctx, dbq.InsertCoverageClosureParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), AgentID: c.Agent, ConnectionID: c.Connection, SandboxSessionID: c.SandboxSession,
		Result: result, Probes: probes, PositiveControlsPassed: v.PositiveControls, NegativeControlsPassed: v.Negative,
		CanaryPassed: v.Canary, SigningKeyJkt: c.SigningKeyJKT, ServerNonce: c.ServerNonce, ResultsSha256: c.ResultsSHA256[:],
		EngineVersion: c.Engine.Version, ApiVersion: c.Engine.APIVersion, Runtime: c.Engine.Runtime,
		ImageDigests: c.ImageDigests, ConfigSha256: c.ConfigSHA256[:], GatewayID: c.Bound.Gateway, ConnectionRevision: b.Revision,
		PackageVersionID: b.PackageVersionID, SessionStartedAt: c.SessionStartedAt, ObservedAt: c.ObservedAt,
		ExpiresAt: c.ObservedAt.Add(s.Freshness.EnforcedTTL),
	})
	if err != nil {
		return ids.UUID{}, err
	}
	if !v.Passed {
		if err := s.RecordInvalidation(ctx, tx, domain.Invalidation{
			Kind: domain.InvClosureFailed, Connection: c.Connection, Agent: &c.Agent, Subject: &row.ID,
		}); err != nil {
			return ids.UUID{}, err
		}
	}
	return row.ID, nil
}

// RecordInvalidation records a change to a scope in the caller's
// transaction (HR-211): an invalidating kind drops ENFORCED at once, and
// the reassess job recomputes the scope.
func (s *Service) RecordInvalidation(ctx context.Context, tx db.TenantTx, inv domain.Invalidation) error {
	if !slices.Contains(domain.InvalidationKinds, inv.Kind) || len(inv.Detail) > 200 || inv.Connection.IsZero() {
		return ErrInvalidation
	}
	var detail *string
	if inv.Detail != "" {
		detail = &inv.Detail
	}
	_, err := dbq.New(tx).InsertCoverageInvalidation(ctx, dbq.InsertCoverageInvalidationParams{
		OrgID: tx.OrgID(), ID: ids.NewV7(), Kind: string(inv.Kind), ConnectionID: inv.Connection, AgentID: inv.Agent,
		SubjectID: inv.Subject, Detail: detail,
	})
	return err
}
