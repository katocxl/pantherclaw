// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package app serves coverage's use cases (G0 M9 track A): recording the
// sandbox's closure evidence and other invalidating changes, the route
// inventory, and the reads of CoverageService.
package app

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/v2"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/protect"
)

// Errors of the coverage use cases.
var (
	ErrNotFound        = pcerr.New(pcerr.NotFound, "COVERAGE_NOT_FOUND", "not found")
	ErrClosure         = pcerr.New(pcerr.InvalidArgument, "INVALID_CLOSURE", "closure evidence needs 1 to 128 probe results with known roles and outcomes, at most 64 configuration checks, a key thumbprint, a server nonce, a runc or runsc engine, 1 to 16 image digests, the session's bindings and times within the last hour")
	ErrClosureStale    = pcerr.New(pcerr.FailedPrecondition, "CLOSURE_STALE", "the scope changed during the sandbox session or since it opened; run it again")
	ErrClosureReplayed = pcerr.New(pcerr.AlreadyExists, "CLOSURE_REPLAYED", "these signed results were already recorded")
	ErrRoute           = pcerr.New(pcerr.InvalidArgument, "INVALID_ROUTE", "an observed route needs an agent, a connection, a sandbox session, the kind direct_api or credential and a locator of 1 to 512 characters")
	ErrNoBinding       = pcerr.New(pcerr.FailedPrecondition, "CONNECTION_UNBOUND", "the connection is retired or its package has no pinned version")
	ErrInvalidation    = pcerr.New(pcerr.InvalidArgument, "INVALID_INVALIDATION", "unknown invalidation kind or a detail longer than 200 characters")
	jktPattern         = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	noncePattern       = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
	digestPattern      = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	enginePattern      = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	apiVersionPattern  = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}$`)
	checkPattern       = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
)

// Service serves coverage as pc_app.
type Service struct {
	Pool      *db.Pool
	Freshness domain.Freshness
	// Verifier reads target-verifier tests per operation; nil reads none, so
	// cooperative and target-enforced channels stay capped (HR-024, HR-210).
	// In M9 a test lifts only the read it tested (founder decision N15).
	Verifier TargetVerifier
	// Clock checks closure times; nil is the wall clock.
	Clock clock.Clock
	// Log reports skipped scopes; nil is slog.Default().
	Log *slog.Logger
	// Notify tells the org of exclusions; nil sends none.
	Notify Notifier
	// Protect holds exclusions for a distinct publisher when the org
	// protects COVERAGE_EXCLUSION (G0 M11 D42); nil holds none.
	Protect *protect.Gate
	// Ents reports the edition the coverage graph needs (F277); nil offers
	// none (fail closed).
	Ents Entitlements
}

func (s *Service) log() *slog.Logger {
	if s.Log == nil {
		return slog.Default()
	}
	return s.Log
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
	if len(c.ConfigChecks) > 64 || slices.ContainsFunc(c.ConfigChecks, func(k domain.ConfigCheck) bool {
		return !checkPattern.MatchString(k.ID) || len(k.Detail) > 512
	}) {
		return false
	}
	if len(c.ImageDigests) == 0 || len(c.ImageDigests) > 16 ||
		slices.ContainsFunc(c.ImageDigests, func(d string) bool { return !digestPattern.MatchString(d) }) {
		return false
	}
	return jktPattern.MatchString(c.SigningKeyJKT) && noncePattern.MatchString(c.ServerNonce) &&
		enginePattern.MatchString(c.Engine.Version) && apiVersionPattern.MatchString(c.Engine.APIVersion) &&
		(c.Engine.Runtime == "runc" || c.Engine.Runtime == "runsc") && !c.Agent.IsZero() && !c.Connection.IsZero() &&
		!c.SandboxSession.IsZero() && !c.Bound.Gateway.IsZero() && !c.Bound.PackageVersion.IsZero() &&
		c.Bound.ConnectionRevision > 0 && !c.SessionStartedAt.After(c.ObservedAt) &&
		!c.ObservedAt.After(now.Add(time.Minute)) && c.ObservedAt.After(now.Add(-time.Hour))
}

// RecordClosure stores the closure evidence of one sandbox session for one
// agent and connection, in the caller's transaction. Only the sandbox
// module calls it, after it verified the signature over the results and
// their server nonce (HR-215); no RPC reaches it otherwise. Coverage
// decides itself whether the closure passed (domain.Evaluate) and gives it
// the freshness contract's expiry (HR-211). A closure is refused when the
// bindings its session opened under (revision, gateway, package version,
// credential version) are no longer the connection's, when an invalidating
// change to the scope came at or after the session opened, or when its
// server nonce was already recorded. A failed one is stored and drops any
// ENFORCED state of the scope at once.
func (s *Service) RecordClosure(ctx context.Context, tx db.TenantTx, c domain.Closure) (ids.UUID, error) {
	now := s.now()
	if !validClosure(c, now) {
		return ids.UUID{}, ErrClosure
	}
	q := dbq.New(tx)
	if err := q.LockCoverageScope(ctx, tx.OrgID().UUID(), c.Agent, c.Connection); err != nil {
		return ids.UUID{}, err
	}
	b, err := q.CoverageBinding(ctx, tx.OrgID(), c.Connection)
	if db.IsNoRows(err) || (err == nil && (b.State == "RETIRED" || b.PackageVersionID == nil)) {
		return ids.UUID{}, ErrNoBinding
	} else if err != nil {
		return ids.UUID{}, err
	}
	bound := domain.Bound{
		ConnectionRevision: b.Revision, Gateway: b.GatewayID, PackageVersion: *b.PackageVersionID,
		CredentialVersion: b.CredentialVersion,
	}
	if !sameBound(c.Bound, bound) {
		return ids.UUID{}, ErrClosureStale
	}
	changes, err := q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
		OrgID: tx.OrgID(), ConnectionID: c.Connection, AgentID: &c.Agent, Since: c.SessionStartedAt,
	})
	if err != nil {
		return ids.UUID{}, err
	}
	if len(changes) > 0 { // only closure-invalidating kinds
		return ids.UUID{}, ErrClosureStale
	}
	v := domain.Evaluate(c.Probes, c.ConfigChecks)
	probes, err := json.Marshal(c.Probes)
	if err != nil {
		return ids.UUID{}, err
	}
	if c.ConfigChecks == nil {
		c.ConfigChecks = []domain.ConfigCheck{}
	}
	checks, err := json.Marshal(c.ConfigChecks)
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
		ImageDigests: c.ImageDigests, ConfigSha256: c.ConfigSHA256[:], ConfigChecks: checks, GatewayID: bound.Gateway,
		ConnectionRevision: bound.ConnectionRevision, PackageVersionID: bound.PackageVersion,
		CredentialVersion: bound.CredentialVersion, SessionStartedAt: c.SessionStartedAt, ObservedAt: c.ObservedAt,
		ExpiresAt: c.ObservedAt.Add(s.Freshness.EnforcedTTL),
	})
	if db.IsNoRows(err) {
		return ids.UUID{}, ErrClosureReplayed
	} else if err != nil {
		return ids.UUID{}, err
	}
	if err := s.enterClosure(ctx, tx, row.ID, result, c); err != nil {
		return ids.UUID{}, err
	}
	if !v.Passed {
		if err := s.RecordInvalidation(ctx, tx, domain.Invalidation{
			Kind: domain.InvClosureFailed, Connection: c.Connection, Agent: &c.Agent, Subject: &row.ID,
		}); err != nil {
			return ids.UUID{}, err
		}
	}
	// The scopes it covers are reassessed at once, in the sandbox's
	// transaction: a passing closure promotes them and a failed one drops
	// them before anyone reads them.
	scopes, err := scopesOf(ctx, q, tx.OrgID(), c.Connection, &c.Agent)
	if err != nil {
		return ids.UUID{}, err
	}
	if _, err := s.reassessScopes(ctx, tx, scopes, nil, Actor, packages{}); err != nil {
		return ids.UUID{}, err
	}
	return row.ID, nil
}

func sameBound(a, b domain.Bound) bool {
	return a.ConnectionRevision == b.ConnectionRevision && a.Gateway == b.Gateway && a.PackageVersion == b.PackageVersion &&
		(a.CredentialVersion == nil) == (b.CredentialVersion == nil) &&
		(a.CredentialVersion == nil || *a.CredentialVersion == *b.CredentialVersion)
}

// RecordRoute records a route the sandbox saw from inside a session, in the
// caller's transaction: a destination the edge refused or a credential it
// stripped or found, as an observed route of the agent and connection for
// every operation (source probe, F443). A first sighting writes a route
// change, so the next read recomputes the scope. It reports whether the
// route was new.
func (s *Service) RecordRoute(ctx context.Context, tx db.TenantTx, r domain.ObservedRoute) (bool, error) {
	if (r.Kind != domain.KindDirectAPI && r.Kind != domain.KindCredential) || r.Agent.IsZero() || r.Connection.IsZero() ||
		r.SandboxSession.IsZero() || r.Locator == "" || utf8.RuneCountInString(r.Locator) > 512 {
		return false, ErrRoute
	}
	id := ids.NewV7()
	row, err := dbq.New(tx).UpsertCoverageRoute(ctx, dbq.UpsertCoverageRouteParams{
		OrgID: tx.OrgID(), ID: id, AgentID: &r.Agent, ConnectionID: r.Connection, Kind: string(r.Kind),
		Locator: &r.Locator, Observation: "observed", Source: "probe", SourceRef: &r.SandboxSession,
		Attributes: []byte(`{}`),
	})
	if err != nil || row.ID != id {
		return false, err
	}
	return true, s.RecordInvalidation(ctx, tx, domain.Invalidation{
		Kind: domain.InvRoute, Connection: r.Connection, Agent: &r.Agent, Subject: &row.ID, Detail: string(r.Kind),
	})
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

// ClosureLedgerKind is the ledger kind of a recorded closure (HR-227).
const ClosureLedgerKind = "sandbox.closure"

// ClosureEntry is the ledger body of a closure: the signed reports it was
// computed from, by run, kind and digest, and the keys that verify them, so
// `pclaw verify` re-checks the closure offline against the probe records
// the bundle carries (HR-227, T-095). Ids are canonical UUID strings; keys
// are base64url raw Ed25519 public keys: ProbeKey verified the sandbox
// report and HostKey the control and canary reports.
type ClosureEntry struct {
	V           int                  `json:"v"`
	Closure     string               `json:"closure"`
	Session     string               `json:"session"`
	Agent       string               `json:"agent"`
	Connections []string             `json:"connections"`
	Result      string               `json:"result"`
	ProbeKey    string               `json:"probe_key"`
	HostKey     string               `json:"host_key"`
	Reports     []ClosureEntryReport `json:"reports"`
	Probes      []ClosureEntryProbe  `json:"probes"`
	RecordedAt  string               `json:"recorded_at"`
}

// ClosureEntryReport names one report of a closure's run.
type ClosureEntryReport struct {
	Run    string `json:"run"`
	Kind   string `json:"kind"`
	SHA256 string `json:"sha256"`
}

// ClosureEntryProbe is one probe's outcome as the closure recorded it.
type ClosureEntryProbe struct {
	Name    string `json:"name"`
	Outcome string `json:"outcome"`
}

// enterClosure appends the closure's sandbox.closure entry to the ledger in
// the caller's transaction, so it is recorded with the closure or not at
// all.
func (s *Service) enterClosure(ctx context.Context, tx db.TenantTx, id ids.UUID, result string, c domain.Closure) error {
	e := ClosureEntry{
		V: 1, Closure: id.String(), Session: c.SandboxSession.String(), Agent: c.Agent.String(),
		Connections: []string{c.Connection.String()}, Result: result,
		ProbeKey: base64.RawURLEncoding.EncodeToString(c.ProbeKey), HostKey: base64.RawURLEncoding.EncodeToString(c.HostKey),
		Reports: []ClosureEntryReport{}, Probes: make([]ClosureEntryProbe, 0, len(c.Probes)),
		RecordedAt: evdomain.Timestamp(s.now()),
	}
	for _, r := range c.Reports {
		e.Reports = append(e.Reports, ClosureEntryReport{Run: r.Run.String(), Kind: r.Kind, SHA256: hex.EncodeToString(r.SHA256[:])})
	}
	for _, p := range c.Probes {
		e.Probes = append(e.Probes, ClosureEntryProbe{Name: p.Name, Outcome: p.Observed})
	}
	slices.SortStableFunc(e.Probes, func(a, b ClosureEntryProbe) int { return strings.Compare(a.Name, b.Name) })
	body, err := evdomain.CanonicalBody(e)
	if err != nil {
		return err
	}
	_, err = ledger.Append(ctx, tx, ClosureLedgerKind, Actor, body)
	return err
}
