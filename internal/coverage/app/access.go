// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"encoding/json/v2"

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

// Disclosure is where an agent gets usable authority at a connection's
// target and what limits it (§39.3). It never carries a secret.
type Disclosure struct {
	Connection ids.UUID
	Agent      *ids.UUID
	Modes      []string
	// Custodian is "gateway", "agent" or "target".
	Custodian         string
	Gateway           ids.UUID
	CredentialVersion int32
	CredentialHosts   []string
	Closure           *dbq.PcCoverageClosure
	Residual          []SnapshotRoute
	Disclosures       []string
}

// GetAccessDisclosure describes a connection's access modes, for one
// agent when named; the caller needs coverage.read over the agent (at org
// scope for the connection alone).
func (s *Service) GetAccessDisclosure(ctx context.Context, connection ids.UUID, agent *ids.UUID) (Disclosure, error) {
	out := Disclosure{Connection: connection, Agent: agent}
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
		switch c.AccessMode {
		case "target_enforced":
			out.Modes, out.Custodian = append(out.Modes, ModeTargetEnforced), "target"
		case "pantherclaw_held":
			out.Modes, out.Custodian, out.Gateway = append(out.Modes, ModePantherClawHeld), "gateway", c.GatewayID
			creds, err := r.q.ListCredentialMetadata(ctx, r.c.Org, connection)
			if err != nil {
				return err
			}
			for _, cr := range creds {
				if cr.State == "ACTIVE" {
					out.CredentialVersion, out.CredentialHosts = cr.Version, cr.AllowedHosts
					break
				}
			}
		default:
			out.Custodian = "agent"
		}
		if agent != nil {
			if out.Closure, err = s.currentClosure(ctx, r.q, r.c.Org, *agent, connection); err != nil {
				return err
			}
			if out.Closure != nil {
				out.Modes = append(out.Modes, ModeConstrainedRuntime)
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

// currentClosure is the agent's newest closure for the connection when it
// still confines it: passed, unexpired, bound to the connection's current
// revision, gateway and package version, and followed by no invalidating
// change.
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
	var probes []domain.ProbeResult
	if err := json.Unmarshal(c.Probes, &probes); err != nil {
		return nil, err
	}
	if !domain.Evaluate(probes, nil).Passed || !s.now().Before(c.ExpiresAt) || b.Revision != c.ConnectionRevision ||
		b.GatewayID != c.GatewayID || b.PackageVersionID == nil || *b.PackageVersionID != c.PackageVersionID {
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
