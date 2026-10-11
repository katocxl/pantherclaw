// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"
	"time"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
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
// secret; the credential is described only by its version and hosts.
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
	// Basis is what verifies the modes; VerifiedAt is the latest passing
	// target-verifier test.
	Basis       []string
	VerifiedAt  *time.Time
	Closure     *dbq.PcCoverageClosure
	Residual    []SnapshotRoute
	Disclosures []string
}

// GetAccessDetail describes a connection's access, for one agent when
// named; the caller needs coverage.read over the agent (at org scope for
// the connection alone).
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
		if s.Verifier != nil {
			if out.VerifiedAt, err = s.Verifier.LastPassed(ctx, r.tx, connection); err != nil {
				return err
			}
		}
		switch c.AccessMode {
		case "target_enforced":
			out.Modes, out.Custodian = append(out.Modes, ModeTargetEnforced), "target"
			out.Scope = []string{"one action: its operation, target and request body"}
			out.Audience = c.AllowedHosts
			out.Expiry, out.IssuedBy = "each action token expires with its permit", "PantherClaw's action tokens"
			out.Basis = append(out.Basis, "the target refuses a request without a valid action token (target-verifier test)")
		case "pantherclaw_held":
			out.Modes, out.Custodian, out.Gateway = append(out.Modes, ModePantherClawHeld), "gateway", c.GatewayID
			out.Expiry, out.IssuedBy = "until the sealed credential is replaced or revoked", "no credential sealed yet"
			out.Basis = append(out.Basis, "the credential is opened only in the gateway's memory at dispatch")
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
		default:
			out.Custodian, out.Expiry, out.IssuedBy = "agent", "unknown: the agent's own access", "unknown"
		}
		if out.Agents, err = r.agentsOf(ctx, connection); err != nil {
			return err
		}
		if agent != nil {
			if out.Closure, err = s.currentClosure(ctx, r.q, r.c.Org, *agent, connection); err != nil {
				return err
			}
			if out.Closure != nil {
				out.Modes = append(out.Modes, ModeConstrainedRuntime)
				out.ExpiresAt = &out.Closure.ExpiresAt
				out.Basis = append(out.Basis, "sandbox closure evidence "+out.Closure.ID.String())
			}
			if out.Residual, err = residual(ctx, r.q, r.c.Org, *agent, connection); err != nil {
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
// are neither mediated nor closed, once each.
func residual(ctx context.Context, q *dbq.Queries, org ids.OrgID, agent, connection ids.UUID) ([]SnapshotRoute, error) {
	rows, err := q.ListCurrentCoverageSnapshotsPage(ctx, dbq.ListCurrentCoverageSnapshotsPageParams{
		OrgID: org, ConnectionID: &connection, AgentID: &agent, MaxRows: 200,
	})
	if err != nil {
		return nil, err
	}
	seen := map[SnapshotRoute]bool{}
	out := []SnapshotRoute{}
	for _, row := range rows {
		var b Snapshot
		if err := json.Unmarshal(row.Body, &b); err != nil {
			return nil, err
		}
		for _, rt := range b.Routes {
			key := SnapshotRoute{Kind: rt.Kind, Channel: rt.Channel, Locator: rt.Locator, Status: rt.Status}
			if rt.Status == string(domain.StatusMediated) || rt.Status == string(domain.StatusClosed) || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, rt)
		}
	}
	return out, nil
}
