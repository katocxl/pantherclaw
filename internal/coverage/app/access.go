// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Access control modes (§39.2), strongest control first.
const (
	ModeTargetEnforced = "target_enforced"
	// ModeNarrowTemporary is per-action access, such as the GitHub App
	// installation tokens of G0 M8; this disclosure reports it once
	// connections record their credential kind.
	ModeNarrowTemporary    = "narrow_temporary"
	ModePantherClawHeld    = "pantherclaw_held"
	ModeConstrainedRuntime = "constrained_runtime"
	ModeAgentHeld          = "agent_held"
)

// ShortExpiryNote is what every disclosure says about expiries (§39.2).
const ShortExpiryNote = "A short expiry alone does not prove that access is limited to one action or that an equivalent route is closed."

// disclosures are what each mode must disclose (§39.2).
var disclosures = map[string]string{
	ModeTargetEnforced: "The target validates each action's token: it accepts only the operations, targets and request bodies PantherClaw authorized.",
	ModePantherClawHeld: "PantherClaw performs approved work with a credential sealed to the connection's gateway, which the agent cannot retrieve. " +
		"The credential's actual target permissions are reported as credential findings; equivalent routes are checked by sandbox closure evidence.",
	ModeConstrainedRuntime: "The containment sandbox confines the agent: its only route is the edge to the gateway, as the closure evidence shows until it expires.",
	ModeAgentHeld:          "The agent can use its own access at the target directly: coverage is partial or unknown unless independent controls close the equivalent routes.",
}

// AccessDetail is where an agent gets usable authority at a connection's
// target and what limits it (§39.2–39.3): who holds it, under which modes,
// with what scope and audience, until when, issued by whom, for which
// agents, verified how, and which routes remain. It never carries a
// secret: the credential is described only by its version and hosts, and
// those, the target hosts and the gateway only to a holder of
// connection.read.
type AccessDetail struct {
	Connection ids.UUID
	Agent      *ids.UUID
	Modes      []string
	// Custodian is "gateway", "agent" or "target".
	Custodian string
	Gateway   ids.UUID
	// Scope and Audience say what the access reaches: the sealed
	// credential's hosts, or the single action a token names.
	Scope    []string
	Audience []string
	// Expiry says how long the access lasts; ExpiresAt is set when it is
	// one time (the confining closure's expiry).
	Expiry    string
	ExpiresAt *time.Time
	// IssuedBy and IssuedAt say where the access came from.
	IssuedBy          string
	IssuedAt          *time.Time
	CredentialVersion int32
	// Agents are the agents with coverage on the connection the caller may
	// read.
	Agents []ids.UUID
	// Basis is what verifies the modes. Verified lists, for each read of
	// the scopes shown, when its latest passing target-verifier test ran:
	// a test vouches only for the read it tested (founder decision N15).
	Basis       []string
	Verified    []VerifiedOperation
	Closure     *dbq.PcCoverageClosure
	Residual    []SnapshotRoute
	Disclosures []string
}

// VerifiedOperation is when the latest passing target-verifier test of
// one operation ran.
type VerifiedOperation struct {
	Operation string
	At        time.Time
}

// withheld is what the detail says of a field only connection.read shows.
const withheld = "withheld: needs connection.read"

// GetAccessDetail describes a connection's access, for one agent when
// named; the caller needs coverage.read over the agent (at org scope for
// the connection alone), and the agent coverage on the connection.
func (s *Service) GetAccessDetail(ctx context.Context, connection ids.UUID, agent *ids.UUID) (AccessDetail, error) {
	out := AccessDetail{Connection: connection, Agent: agent}
	err := s.read(ctx, func(ctx context.Context, r *readers) error {
		if ok, err := r.can(ctx, agent); db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil || !ok {
			return orNotFound(err)
		}
		c, err := r.q.GetConnection(ctx, r.c.Org, connection)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		scopes, err := scopesOf(ctx, r.q, r.c.Org, connection, agent)
		if err != nil {
			return err
		}
		if agent != nil && len(scopes) == 0 {
			return ErrNotFound // the agent has no coverage on this connection
		}
		// The credential, the hosts and the gateway are the connection's
		// configuration, which coverage.read alone does not show.
		config := r.c.Can(td.PermConnectionRead, td.OrgPath(r.c.Org))
		switch c.AccessMode {
		case "target_enforced":
			out.Modes, out.Custodian = append(out.Modes, ModeTargetEnforced), "target"
			out.Scope = []string{"one action: its operation, target and request body"}
			out.Expiry, out.IssuedBy = "each action token expires with its permit", "PantherClaw's action tokens"
			out.Basis = append(out.Basis, "the target refuses a request without a valid action token, as a target-verifier "+
				"test of a read shows; in M9 a test vouches only for the read it tested, and writes stay PARTIAL")
			if config {
				out.Audience = c.AllowedHosts
			}
		case "pantherclaw_held":
			out.Modes, out.Custodian = append(out.Modes, ModePantherClawHeld), "gateway"
			out.Expiry, out.IssuedBy = "until the sealed credential is replaced or revoked", withheld
			out.Basis = append(out.Basis, "the credential is opened only in the gateway's memory at dispatch")
			if config {
				out.Gateway, out.IssuedBy = c.GatewayID, "no credential sealed yet"
				creds, err := r.q.ListCredentialMetadata(ctx, r.c.Org, connection)
				if err != nil {
					return err
				}
				for _, cr := range creds {
					if cr.State == "ACTIVE" {
						at := cr.CreatedAt
						out.CredentialVersion, out.Scope, out.Audience = cr.Version, cr.AllowedHosts, cr.AllowedHosts
						out.IssuedBy, out.IssuedAt = "sealed by "+cr.CreatedBy, &at
						break
					}
				}
			}
		default:
			out.Custodian, out.Expiry, out.IssuedBy = "agent", "unknown: the agent's own access", "unknown"
		}
		if out.Verified, err = s.verifiedReads(ctx, r, connection, scopes); err != nil {
			return err
		}
		if out.Agents, err = r.agentsOf(ctx, connection); err != nil {
			return err
		}
		if agent != nil {
			if out.Closure, err = s.currentClosure(ctx, r.q, r.c.Org, *agent, connection); err != nil {
				return err
			}
			var current *ids.UUID
			if out.Closure != nil {
				current = &out.Closure.ID
				out.Modes = append(out.Modes, ModeConstrainedRuntime)
				out.ExpiresAt = &out.Closure.ExpiresAt
				out.Basis = append(out.Basis, "sandbox closure evidence "+out.Closure.ID.String())
			}
			if out.Residual, err = s.residual(ctx, r, *agent, connection, current); err != nil {
				return err
			}
		}
		if out.Custodian == "agent" {
			out.Modes = append(out.Modes, ModeAgentHeld)
		}
		for _, m := range out.Modes {
			out.Disclosures = append(out.Disclosures, disclosures[m])
		}
		out.Disclosures = append(out.Disclosures, ShortExpiryNote)
		return nil
	})
	return out, err
}

// verifiedReads lists, for each operation of scopes that the connection's
// pinned package defines as a read, when its latest passing
// target-verifier test ran; operations without one are left out.
func (s *Service) verifiedReads(ctx context.Context, r *readers, connection ids.UUID, scopes []domain.Scope) ([]VerifiedOperation, error) {
	if s.Verifier == nil || len(scopes) == 0 {
		return nil, nil
	}
	b, err := r.q.CoverageBinding(ctx, r.c.Org, connection)
	if err != nil || b.PackageVersionID == nil {
		return nil, err
	}
	pkg, err := packages{}.get(ctx, r.q, r.c.Org, *b.PackageVersionID)
	if err != nil {
		return nil, err
	}
	var out []VerifiedOperation
	for _, sc := range scopes {
		if !readOnly(pkg, sc.Operation) || slices.ContainsFunc(out, func(v VerifiedOperation) bool { return v.Operation == sc.Operation }) {
			continue
		}
		at, err := s.Verifier.LastPassed(ctx, r.tx, connection, sc.Operation)
		if err != nil {
			return nil, err
		}
		if at != nil {
			out = append(out, VerifiedOperation{Operation: sc.Operation, At: *at})
		}
	}
	return out, nil
}

// agentsOf lists the agents with coverage on a connection that the caller
// may read.
func (r *readers) agentsOf(ctx context.Context, connection ids.UUID) ([]ids.UUID, error) {
	rows, err := r.q.CoverageAgentsOfConnection(ctx, r.c.Org, connection)
	if err != nil {
		return nil, err
	}
	out := []ids.UUID{}
	for _, a := range rows {
		if ok, err := r.can(ctx, &a); err != nil {
			return nil, err
		} else if ok {
			out = append(out, a)
		}
	}
	return out, nil
}

// currentClosure is the agent's newest closure for the connection when it
// still confines it: passed, unexpired, taken under the connection's
// current bindings, and followed by no invalidating change.
func (s *Service) currentClosure(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, connection ids.UUID) (*dbq.PcCoverageClosure, error) {
	c, err := q.LatestCoverageClosure(ctx, org, agent, connection)
	if db.IsNoRows(err) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	b, err := q.CoverageBinding(ctx, org, connection)
	if err != nil {
		return nil, err
	}
	rec, err := closureRecord(c)
	if err != nil {
		return nil, err
	}
	if b.PackageVersionID == nil || !domain.Evaluate(rec.Probes, rec.ConfigChecks).Passed || !s.now().Before(c.ExpiresAt) ||
		!sameBound(rec.Bound, domain.Bound{
			ConnectionRevision: b.Revision, Gateway: b.GatewayID, PackageVersion: *b.PackageVersionID,
			CredentialVersion: b.CredentialVersion,
		}) {
		return nil, nil
	}
	changes, err := q.CoverageInvalidationsSince(ctx, dbq.CoverageInvalidationsSinceParams{
		OrgID: org, ConnectionID: connection, AgentID: &agent, Since: c.SessionStartedAt,
	})
	if err != nil || len(changes) > 0 {
		return nil, err
	}
	return &c, nil
}

// residual lists the routes of the agent's scopes on the connection that
// are neither mediated nor closed by the current closure, once each. Each
// scope reads as its record does now: a lapsed one as recomputed, so a
// route a stale snapshot showed mediated or closed is open again, and so
// is a route an earlier closure than the current one closed.
func (s *Service) residual(ctx context.Context, r *readers, agent, connection ids.UUID, current *ids.UUID) ([]SnapshotRoute, error) {
	rows, err := r.q.ListCurrentCoverageSnapshotsPage(ctx, dbq.ListCurrentCoverageSnapshotsPageParams{
		OrgID: r.c.Org, ConnectionID: &connection, AgentID: &agent, MaxRows: 200,
	})
	if err != nil {
		return nil, err
	}
	pkgs, now := packages{}, s.now()
	seen := map[SnapshotRoute]bool{}
	out := []SnapshotRoute{}
	for _, row := range rows {
		sc := domain.Scope{Agent: row.AgentID, Connection: row.ConnectionID, Operation: row.Operation}
		rec, err := s.record(ctx, r.tx, sc, &row, false, pkgs, now)
		if err != nil {
			return nil, err
		}
		routes := rec.Body.Routes
		if rec.Recomputed != nil {
			routes = snapshotOf(sc, *rec.Recomputed, nil).Routes
		}
		for _, rt := range routes {
			closed := rt.Status == string(domain.StatusClosed) && current != nil && rt.Closure == current.String()
			key := SnapshotRoute{Kind: rt.Kind, Channel: rt.Channel, Locator: rt.Locator, Status: rt.Status}
			if rt.Status == string(domain.StatusMediated) || closed || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, rt)
		}
	}
	return out, nil
}
