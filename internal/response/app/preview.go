// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
	rdomain "github.com/katocxl/pantherclaw/internal/response/domain"
)

// maxPreviewRuns is how many active runs a preview counts exactly.
const maxPreviewRuns = 1000

// Preview is what a containment control would do (D23, F013): the scope,
// the active runs and agents it stops, the waiting actions it invalidates,
// the gateways that enforce it, the alternative (bypass) paths it does not
// close and what it cannot know. Digest is the SHA-256 of the canonical
// preview without the reach, which a wider control must be confirmed
// against (HR-252); reach is computed from exposure snapshots and shown
// beside it.
type Preview struct {
	ScopeType string `json:"scope_type"`
	ScopeID   string `json:"scope_id"`
	Control   string `json:"control"`
	Operation string `json:"operation,omitzero"`
	Narrow    bool   `json:"narrow"`
	// Runs are the active runs the control covers (ids, sorted); RunsOver
	// says there were more than maxPreviewRuns.
	Runs     []ids.UUID `json:"runs"`
	RunsOver bool       `json:"runs_over,omitzero"`
	Agents   []ids.UUID `json:"agents"`
	// Waiting is how many waiting approval requests of those runs a deny
	// control voids at their next use.
	Waiting  int64      `json:"waiting"`
	Gateways []ids.UUID `json:"gateways"`
	// Alternatives are bypass routes ("agent:connection:operation" with
	// OBSERVE_ONLY or UNKNOWN coverage) the control does not close.
	Alternatives []string `json:"alternatives"`
	// Unknown lists what the preview could not establish.
	Unknown []string `json:"unknown"`

	Digest []byte `json:"-"`
	// Reach is the before and after reach (Team and above, through the
	// exposure stream), or nil with ReachNote saying why not.
	Reach     *reflexdomain.ReachDiff `json:"-"`
	ReachNote string                  `json:"-"`
}

// preview computes a control's preview in tx, without the reach.
func preview(ctx context.Context, tx db.TenantTx, org ids.OrgID, c rdomain.Control) (Preview, error) {
	q := dbq.New(tx)
	p := Preview{
		ScopeType: c.ScopeType, ScopeID: c.ScopeID, Control: c.Control, Operation: c.Operation, Narrow: c.Narrow(),
		Runs: []ids.UUID{}, Agents: []ids.UUID{}, Gateways: []ids.UUID{}, Alternatives: []string{}, Unknown: []string{},
	}
	if c.ScopeType != rdomain.ScopeResource {
		runs, err := q.ScopeActiveRuns(ctx, org, c.ScopeType, c.ScopeID)
		if err != nil {
			return Preview{}, err
		}
		if len(runs) > maxPreviewRuns {
			runs, p.RunsOver = runs[:maxPreviewRuns], true
		}
		for _, r := range runs {
			p.Runs = append(p.Runs, r.ID)
			if !slices.Contains(p.Agents, r.AgentID) {
				p.Agents = append(p.Agents, r.AgentID)
			}
		}
	} else {
		p.Unknown = append(p.Unknown, "a resource scope covers whichever runs act on the resource; they are not known in advance")
	}
	if c.ScopeType == rdomain.ScopeAgent {
		if id, err := ids.ParseUUID(c.ScopeID); err == nil && !slices.Contains(p.Agents, id) {
			p.Agents = append(p.Agents, id)
		}
	}
	slices.SortFunc(p.Agents, compareUUID)
	if len(p.Runs) > 0 && c.Control != rdomain.HoldWrites {
		n, err := q.WaitingHoldsOfRuns(ctx, org, p.Runs)
		if err != nil {
			return Preview{}, err
		}
		p.Waiting = n
	}
	gws, err := q.ScopeGateways(ctx, org, c.ScopeType, c.ScopeID)
	if err != nil {
		return Preview{}, err
	}
	p.Gateways = append(p.Gateways, gws...)
	if len(p.Agents) > 0 {
		cov, err := q.AgentCoverage(ctx, org, p.Agents)
		if err != nil {
			return Preview{}, err
		}
		covered := map[ids.UUID]bool{}
		for _, r := range cov {
			covered[r.AgentID] = true
			if bypass(r.State) {
				p.Alternatives = append(p.Alternatives, routeID(r.AgentID, r.ConnectionID, r.Operation))
			}
		}
		for _, a := range p.Agents {
			if !covered[a] {
				p.Unknown = append(p.Unknown, "agent "+a.String()+" has no coverage record, so its other routes are unknown")
			}
		}
	}
	if c.ScopeType == rdomain.ScopeConnection {
		p.Unknown = append(p.Unknown, "routes that serve every agent of the connection are not attributed to agents")
	}
	sum, err := digest(p)
	if err != nil {
		return Preview{}, err
	}
	p.Digest = sum
	return p, nil
}

func digest(p Preview) ([]byte, error) {
	b, err := json.Marshal(p, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// bypass reports whether a coverage state leaves a route the gateway does
// not mediate (D22).
func bypass(state string) bool { return state == "OBSERVE_ONLY" || state == "UNKNOWN" }

func routeID(agent, connection ids.UUID, operation string) string {
	return agent.String() + ":" + connection.String() + ":" + operation
}

func compareUUID(a, b ids.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return 0
}

// PreviewIn computes a control's preview in tx (D23), without the reach:
// what Contain compares a wider control's digest against.
func (s *Containment) PreviewIn(ctx context.Context, tx db.TenantTx, c rdomain.Control) (Preview, error) {
	c, err := c.Canonical()
	if err != nil {
		return Preview{}, err
	}
	if err := exists(ctx, dbq.New(tx), tx.OrgID(), c); err != nil {
		return Preview{}, err
	}
	return preview(ctx, tx, tx.OrgID(), c)
}
