// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package cohorts

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

const production = "PRODUCTION"

// What one read holds at most (the queries' LIMITs): a list this long may
// have been cut, and the result says so (D71 G5).
const (
	maxGrantsRead   = 2000
	maxChangesRead  = 500
	maxReleasesRead = 100
)

// AgentFacts is what the fleet overview and the queue show about an agent.
type AgentFacts struct {
	dbq.FleetAgentFactsRow
}

// LastRun returns when the agent last started a run (zero: never).
func (f AgentFacts) LastRun() time.Time {
	if f.LastRunAt.Unix() <= 0 {
		return time.Time{}
	}
	return f.LastRunAt
}

// Departure is an active grant of a cohort agent beyond the baseline.
type Departure struct {
	Grant, Agent ids.UUID
	Reason       string
}

// Queue is what a cohort needs from a person.
type Queue struct {
	// Unowned agents have no owner; Unpromoted are in a PRODUCTION
	// environment without any promotion; Pending have approvals waiting.
	Unowned, Unpromoted, Pending []AgentFacts
	// OverBaseline are active grants beyond the cohort's baseline (empty
	// without a baseline).
	OverBaseline []Departure
	// Truncated: the cohort has more agents or active grants than the
	// queue reads (D71 G5).
	Truncated bool
	// Notes say what the queue could not include.
	Notes []string
}

// AutomationExceptionsNote is the queue's note until governed automations
// report their exceptions per agent.
const AutomationExceptionsNote = "automation exceptions are listed once governed automations report them per agent"

func facts(ctx context.Context, q *dbq.Queries, org ids.OrgID, agents []ids.UUID) ([]AgentFacts, error) {
	if len(agents) == 0 {
		return nil, nil
	}
	rows, err := q.FleetAgentFacts(ctx, org, agents)
	if err != nil {
		return nil, err
	}
	out := make([]AgentFacts, len(rows))
	for i, r := range rows {
		out[i] = AgentFacts{r}
	}
	return out, nil
}

// GetQueue returns a cohort's queue (agent.read, Team).
func (s *Service) GetQueue(ctx context.Context, id ids.UUID) (Queue, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Queue{}, err
	}
	var out Queue
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
		out.Truncated = truncated
		fs, err := facts(ctx, q, c.Org, agents)
		if err != nil {
			return err
		}
		for _, f := range fs {
			if f.State == "RETIRED" {
				continue
			}
			if f.OwnerUserID == nil {
				out.Unowned = append(out.Unowned, f)
			}
			if f.EnvironmentKind == production && len(f.Promoted) == 0 {
				out.Unpromoted = append(out.Unpromoted, f)
			}
			if f.PendingApprovals > 0 {
				out.Pending = append(out.Pending, f)
			}
		}
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
			for _, g := range grants {
				if why := beyond(b, g); why != "" {
					out.OverBaseline = append(out.OverBaseline, Departure{Grant: g.ID, Agent: g.AgentID, Reason: why})
				}
			}
		}
		out.Notes = append(out.Notes, AutomationExceptionsNote)
		return nil
	}, db.ReadOnly())
	return out, err
}

// beyond says how a grant departs from a baseline ("" when it stays
// within): bounds wider than the baseline's, or a lifetime longer than
// its TTL.
func beyond(b Baseline, g dbq.FleetActiveGrantsRow) string {
	var bounds gdomain.Bounds
	if err := json.Unmarshal(g.Bounds, &bounds); err != nil {
		return "its bounds cannot be read"
	}
	if w := bounds.Within(b.Bounds); w != nil {
		return "bounds: " + w.Error()
	}
	if b.TTLSeconds > 0 && g.ExpiresAt.Sub(g.NotBefore) > time.Duration(b.TTLSeconds)*time.Second {
		return fmt.Sprintf("lasts %s, the baseline %s", g.ExpiresAt.Sub(g.NotBefore).Round(time.Minute), time.Duration(b.TTLSeconds)*time.Second)
	}
	return ""
}

// Changes is what moved for a cohort's agents since a time.
type Changes struct {
	Since           time.Time
	MembersAdded    []dbq.FleetMembersAddedSinceRow
	GrantRevisions  []dbq.FleetGrantRevisionsSinceRow
	GrantRevoked    []dbq.FleetGrantRevocationsSinceRow
	PolicyVersions  []dbq.FleetPolicyVersionsPublishedSinceRow
	PackageVersions []dbq.FleetPackageActivationsSinceRow
	Promotions      []dbq.PcAgentPromotion
	// Truncated: some list holds only its first rows (D71 G5).
	Truncated bool
}

// GetChanges returns what moved for a cohort's agents since a time, at
// most 31 days back (agent.read, Team): members added, grants issued,
// revised and revoked, policy versions published, package versions
// activated and promotions made or revoked.
func (s *Service) GetChanges(ctx context.Context, id ids.UUID, since time.Time) (Changes, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Changes{}, err
	}
	out := Changes{Since: since}
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		now, err := q.DBNow(ctx)
		if err != nil {
			return err
		}
		if out.Since.IsZero() || out.Since.Before(now.Add(-31*24*time.Hour)) {
			out.Since = now.Add(-31 * 24 * time.Hour)
		}
		co, _, err := readableCohort(ctx, q, c, id, false)
		if err != nil {
			return err
		}
		agents, truncated, err := readable(ctx, q, c, co)
		if err != nil {
			return err
		}
		out.Truncated = truncated
		if out.MembersAdded, err = q.FleetMembersAddedSince(ctx, c.Org, id, out.Since); err != nil {
			return err
		}
		visible := map[ids.UUID]bool{}
		for _, a := range agents {
			visible[a] = true
		}
		out.Truncated = out.Truncated || len(out.MembersAdded) >= maxChangesRead
		kept := out.MembersAdded[:0]
		for _, m := range out.MembersAdded {
			if visible[m.AgentID] {
				kept = append(kept, m)
			}
		}
		out.MembersAdded = kept
		if out.GrantRevisions, err = q.FleetGrantRevisionsSince(ctx, c.Org, agents, out.Since); err != nil {
			return err
		}
		if out.GrantRevoked, err = q.FleetGrantRevocationsSince(ctx, c.Org, agents, &out.Since); err != nil {
			return err
		}
		if c.Can(td.PermPolicyRead, td.OrgPath(c.Org)) {
			if out.PolicyVersions, err = q.FleetPolicyVersionsPublishedSince(ctx, c.Org, &out.Since); err != nil {
				return err
			}
		}
		if c.Can(td.PermPackageRead, td.OrgPath(c.Org)) {
			if out.PackageVersions, err = q.FleetPackageActivationsSince(ctx, c.Org, out.Since); err != nil {
				return err
			}
		}
		if out.Promotions, err = q.FleetPromotionsSince(ctx, c.Org, agents, out.Since); err != nil {
			return err
		}
		out.Truncated = out.Truncated || len(out.GrantRevisions) >= maxChangesRead ||
			len(out.GrantRevoked) >= maxChangesRead || len(out.Promotions) >= maxChangesRead ||
			len(out.PolicyVersions) >= maxReleasesRead || len(out.PackageVersions) >= maxReleasesRead
		return nil
	}, db.ReadOnly())
	return out, err
}

// Overview is one page of the fleet overview.
type Overview struct {
	Agents []AgentFacts
	Next   *ids.UUID
}

// GetFleetOverview lists every agent the caller may read with its owner,
// last run, promoted operations and active grants (agent.read, Team; no
// cohort needed).
func (s *Service) GetFleetOverview(ctx context.Context, after *ids.UUID, limit int) (Overview, error) {
	c, err := s.reader(ctx)
	if err != nil {
		return Overview{}, err
	}
	if limit <= 0 || limit > maxList {
		limit = maxList
	}
	var out Overview
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		page, err := q.FleetAgentIDs(ctx, c.Org, after, int32(limit+1)) //nolint:gosec // ≤ 201
		if err != nil {
			return err
		}
		if len(page) > limit {
			page = page[:limit]
			last := page[limit-1]
			out.Next = &last
		}
		var shown []ids.UUID
		for _, id := range page {
			_, ok, err := visible(ctx, q, c, id, PermRead)
			if err != nil {
				return err
			}
			if ok {
				shown = append(shown, id)
			}
		}
		out.Agents, err = facts(ctx, q, c.Org, shown)
		return err
	}, db.ReadOnly())
	return out, err
}
