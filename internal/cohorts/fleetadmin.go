// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohorts

import (
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"slices"

	aapp "github.com/katocxl/pantherclaw/internal/agents/app"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Large-fleet administration (G0 M18 D154; F602, HR-478, HR-480, T-213):
// what exception groups, bulk simulation and the per-cohort findings read
// of cohorts. Every agent a caller is shown is one it may read (agent.read
// at the agent's path): the rest are left out and never counted.

// ReadableAgents returns the cohort's agents, retired ones left out, that
// the caller may read, in the caller's transaction, and whether the
// cohort held more than could be read (MaxMembers*2). ErrNotFound when
// the cohort does not exist or is outside the caller's scope.
func ReadableAgents(ctx context.Context, tx db.TenantTx, c tapp.Caller, cohort ids.UUID) ([]ids.UUID, bool, error) {
	q := dbq.New(tx)
	co, _, err := readableCohort(ctx, q, c, cohort, false)
	if err != nil {
		return nil, false, err
	}
	rows, err := agentsOf(ctx, q, c.Org, co, nil, maxResolved+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > maxResolved
	if truncated {
		rows = rows[:maxResolved]
	}
	var out []ids.UUID
	for _, r := range rows {
		if r.State == "RETIRED" {
			continue
		}
		path, err := aapp.PathOf(ctx, q, agentOf(r))
		if err != nil {
			return nil, false, err
		}
		if c.Can(PermRead, path) {
			out = append(out, r.ID)
		}
	}
	return out, truncated, nil
}

// ReadableCohorts reports which of the cohorts the caller may read
// (agent.read at the cohort's scope); a cohort that no longer exists is
// not readable.
func ReadableCohorts(ctx context.Context, tx db.TenantTx, c tapp.Caller, cohorts []ids.UUID) (map[ids.UUID]bool, error) {
	out := make(map[ids.UUID]bool, len(cohorts))
	if len(cohorts) == 0 {
		return out, nil
	}
	if c.Can(PermRead, td.OrgPath(c.Org)) {
		// The org's scope holds every cohort's.
		for _, id := range cohorts {
			out[id] = true
		}
		return out, nil
	}
	q := dbq.New(tx)
	for _, id := range cohorts {
		if _, _, err := readableCohort(ctx, q, c, id, false); err == nil {
			out[id] = true
		} else if err != ErrNotFound { //nolint:errorlint // readableCohort returns the sentinel itself
			return nil, err
		}
	}
	return out, nil
}

// Memberships maps each agent to the cohorts holding it, over the org's
// first limit cohorts by name, retired agents left out, for a caller that
// already authorized the read (bulk simulation counts its decisions per
// cohort, D154).
func Memberships(ctx context.Context, tx db.TenantTx, limit int) (map[ids.UUID][]ids.UUID, error) {
	q := dbq.New(tx)
	out := map[ids.UUID][]ids.UUID{}
	var after *string
	seen := 0
	for seen < limit {
		n := min(maxList, limit-seen)
		rows, err := q.ListFleetCohorts(ctx, tx.OrgID(), after, int32(n)) //nolint:gosec // ≤ maxList
		if err != nil {
			return nil, err
		}
		for _, r := range rows {
			co := dbq.PcFleetCohort{OrgID: r.OrgID, ID: r.ID, Name: r.Name, Rule: r.Rule}
			agents, err := agentsOf(ctx, q, tx.OrgID(), co, nil, maxResolved)
			if err != nil {
				return nil, err
			}
			for _, a := range agents {
				if a.State != "RETIRED" {
					out[a.ID] = append(out[a.ID], r.ID)
				}
			}
		}
		seen += len(rows)
		if len(rows) < n {
			break
		}
		last := rows[len(rows)-1].Name
		after = &last
	}
	return out, nil
}

// Count is how many findings of a kind the cohort's readable agents have,
// and how many of those agents have one.
type Count struct {
	Findings, Agents int64
	// Shown is false when the caller lacks the permission the kind needs,
	// so it is not counted at all.
	Shown bool
}

// Findings are a cohort's aggregated findings (D154; HR-480): counts over
// the cohort's agents the caller may read, never stored.
type Findings struct {
	// Agents is how many of the cohort's agents the counts cover.
	Agents int
	// Coverage counts open coverage findings (coverage.read at the org).
	Coverage Count
	// Departures counts active grants beyond the cohort's baseline.
	Departures Count
	// FailedTargets counts FAILED rollout targets of the rollouts still
	// followed: open ones and those completed in the last 7 days
	// (policy.read at the org).
	FailedTargets Count
	// ActiveExceptions counts exceptions that waive something now
	// (policy.read at the org).
	ActiveExceptions Count
	// Truncated: the cohort has more agents or active grants than are
	// read (D71 G5).
	Truncated bool
}

// GetFindings returns a cohort's aggregated findings (agent.read at the
// cohort's scope, Team). Only agents the caller may read are counted
// (HR-480, T-213), and each kind needs the permission its own reads need.
func (s *Service) GetFindings(ctx context.Context, id ids.UUID) (Findings, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Findings{}, err
	}
	var out Findings
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		co, _, err := readableCohort(ctx, q, c, id, false)
		if err != nil {
			return err
		}
		agents, truncated, err := readable(ctx, q, c, co)
		if err != nil {
			return err
		}
		out.Agents, out.Truncated = len(agents), truncated
		org := td.OrgPath(c.Org)
		if c.Can(td.PermCoverageRead, org) {
			r, err := q.CohortOpenCoverageFindings(ctx, c.Org, agents)
			if err != nil {
				return err
			}
			out.Coverage = Count{Findings: r.N, Agents: r.Agents, Shown: true}
		}
		if c.Can(td.PermPolicyRead, org) {
			f, err := q.CohortFailedRolloutTargets(ctx, c.Org, agents)
			if err != nil {
				return err
			}
			out.FailedTargets = Count{Findings: f.N, Agents: f.Agents, Shown: true}
			x, err := q.CohortActiveExceptions(ctx, c.Org, agents)
			if err != nil {
				return err
			}
			out.ActiveExceptions = Count{Findings: x.N, Agents: x.Agents, Shown: true}
		}
		out.Departures.Shown = true
		if co.Baseline != nil && len(agents) > 0 {
			var b Baseline
			if err := json.Unmarshal(co.Baseline, &b); err != nil {
				return err
			}
			grants, err := q.FleetActiveGrants(ctx, c.Org, agents)
			if err != nil {
				return err
			}
			out.Truncated = out.Truncated || len(grants) >= maxGrantsRead
			with := map[ids.UUID]bool{}
			for _, g := range grants {
				if beyond(b, g) != "" {
					out.Departures.Findings++
					with[g.AgentID] = true
				}
			}
			out.Departures.Agents = int64(len(with))
		}
		return nil
	}, db.ReadOnly())
	return out, err
}

// Snapshot returns a cohort's agents, retired ones left out, at most
// limit, for a caller that already authorized the read, and whether the
// cohort held more than that (an exception group's snapshot at approval,
// HR-477). ErrNotFound when the cohort does not exist.
func Snapshot(ctx context.Context, tx db.TenantTx, cohort ids.UUID, limit int) ([]ids.UUID, bool, error) {
	q := dbq.New(tx)
	co, err := q.GetFleetCohort(ctx, tx.OrgID(), cohort)
	if db.IsNoRows(err) {
		return nil, false, ErrNotFound
	} else if err != nil {
		return nil, false, err
	}
	rows, err := agentsOf(ctx, q, tx.OrgID(), co, nil, maxResolved+1)
	if err != nil {
		return nil, false, err
	}
	truncated := len(rows) > maxResolved
	var out []ids.UUID
	for _, r := range rows[:min(len(rows), maxResolved)] {
		if r.State == "RETIRED" {
			continue
		}
		if len(out) == limit {
			return out, true, nil
		}
		out = append(out, r.ID)
	}
	return out, truncated, nil
}

// DefinitionDigest is SHA-256 of the JCS form of what decides a cohort's
// agents: its rule and its static members. An exception group's request
// binds it, so a cohort edited before the approval voids the request
// (HR-477). ErrNotFound when the cohort does not exist.
func DefinitionDigest(ctx context.Context, tx db.TenantTx, cohort ids.UUID) ([32]byte, error) {
	q := dbq.New(tx)
	co, err := q.GetFleetCohort(ctx, tx.OrgID(), cohort)
	if db.IsNoRows(err) {
		return [32]byte{}, ErrNotFound
	} else if err != nil {
		return [32]byte{}, err
	}
	static, err := q.FleetCohortStaticAgents(ctx, tx.OrgID(), cohort)
	if err != nil {
		return [32]byte{}, err
	}
	members := make([]string, len(static))
	for i, a := range static {
		members[i] = a.ID.String()
	}
	slices.Sort(members)
	rule := jsontext.Value("null")
	if co.Rule != nil {
		rule = jsontext.Value(co.Rule)
	}
	raw, err := json.Marshal(map[string]any{"cohort": co.ID.String(), "rule": rule, "static_members": members})
	if err != nil {
		return [32]byte{}, err
	}
	v := jsontext.Value(raw)
	if err := v.Canonicalize(); err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(v), nil
}
