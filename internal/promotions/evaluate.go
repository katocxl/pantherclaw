// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// identityStates are the agent states at or after VERIFIED that can work.
var identityStates = []string{"VERIFIED", "OBSERVED", "PARTIALLY_PROTECTED", "PROTECTED"}

// subject is what the checks read about an agent, once per evaluation.
type subject struct {
	org ids.OrgID
	row dbq.PromotionSubjectRow
	env ids.UUID
	// bundle is the published policy (nil: none is published).
	bundle *pdomain.Bundle
	// catalog is what the agent's connections reach, with consequences.
	catalog catalog
	// windows counts the org's change windows.
	windows int32
}

// load reads what every operation's checks need.
func load(ctx context.Context, q *dbq.Queries, org ids.OrgID, row dbq.PromotionSubjectRow, env ids.UUID, c catalog) (*subject, error) {
	s := &subject{org: org, row: row, env: env, catalog: c}
	pub, err := q.GetPublishedPolicy(ctx, org)
	switch {
	case db.IsNoRows(err):
	case err != nil:
		return nil, err
	default:
		var b pdomain.Bundle
		if err := json.Unmarshal(pub.Bundle, &b); err != nil {
			return nil, fmt.Errorf("promotions: published policy %s: %w", pub.ID, err)
		}
		s.bundle = &b
	}
	if s.windows, err = q.PromotionChangeWindows(ctx, org); err != nil {
		return nil, err
	}
	return s, nil
}

// evaluate runs every check for each operation (D39). failureBehavior is
// the declared behavior ("" when none is declared yet).
func (s *subject) evaluate(ctx context.Context, q *dbq.Queries, ops []string, failureBehavior string, now time.Time) ([]Readiness, error) {
	out := make([]Readiness, 0, len(ops))
	for _, op := range ops {
		r := Readiness{Operation: op}
		r.Checks = append(r.Checks, s.owner(), s.identity(), s.tests(op))
		c, err := s.approvals(ctx, q, op)
		if err != nil {
			return nil, err
		}
		r.Checks = append(r.Checks, c)
		if c, err = s.coverage(ctx, q, op, now); err != nil {
			return nil, err
		}
		r.Checks = append(r.Checks, c, declared(failureBehavior))
		out = append(out, r)
	}
	return out, nil
}

func (s *subject) owner() Check {
	switch {
	case s.row.OwnerUserID == nil:
		return Check{Name: CheckOwner, Detail: "the agent has no owner; claim it first"}
	case !s.row.OwnerActive:
		return Check{Name: CheckOwner, Detail: "the agent's owner " + s.row.OwnerUserID.String() + " is not an active person"}
	}
	return Check{Name: CheckOwner, Passed: true, Detail: "owner " + s.row.OwnerUserID.String() + " is active"}
}

func (s *subject) identity() Check {
	switch {
	case !slices.Contains(identityStates, s.row.State):
		return Check{Name: CheckIdentity, Detail: "the agent is " + s.row.State + "; it must be VERIFIED or later"}
	case s.row.ActiveInstances < 1:
		return Check{Name: CheckIdentity, Detail: "the agent has no admitted, unexpired instance"}
	}
	return Check{Name: CheckIdentity, Passed: true, Detail: fmt.Sprintf("%s with %d active instance(s)", s.row.State, s.row.ActiveInstances)}
}

// inEnv reports whether an environment list (empty: every environment)
// names the promotion's environment.
func (s *subject) inEnv(envs []string) bool {
	return len(envs) == 0 || slices.Contains(envs, s.env.String())
}

// tests: the published policy has at least one scenario case of the
// operation in this environment (a case naming no environment counts).
func (s *subject) tests(op string) Check {
	if s.bundle == nil {
		return Check{Name: CheckTests, Detail: "no policy is published"}
	}
	var n int
	for _, tc := range s.bundle.Tests {
		if tc.Action.Operation == op && (tc.Action.Environment == "" || tc.Action.Environment == s.env.String()) {
			n++
		}
	}
	if n == 0 {
		return Check{Name: CheckTests, Detail: fmt.Sprintf("published policy %s v%d has no scenario test of %s in this environment",
			s.bundle.ID, s.bundle.Version, op)}
	}
	return Check{Name: CheckTests, Passed: true, Detail: fmt.Sprintf("%d scenario test(s) in the published policy", n)}
}

// approvals: every hold the action can meet has at least one eligible
// approver (D71 G10). Holds come from the published policy's approval
// rules on the operation, and on each consequence its active packages'
// consequence rules predict for it (as the Authority applies them), in
// this environment. An eligible approver is an active person holding the
// role where the agent lives, not one of its owners when the requirement
// is independent (code reviewers and release approvers always are). A
// release-window hold (window: true, or a release approver) counts only
// inside a change window, so the org needs one.
func (s *subject) approvals(ctx context.Context, q *dbq.Queries, op string) (Check, error) {
	if s.bundle == nil {
		return Check{Name: CheckApprovals, Passed: true, Detail: "no policy is published, so nothing is held for approval"}, nil
	}
	reached := append([]string{op}, s.catalog.consequences[op]...)
	var rules, missing []string
	for _, r := range s.bundle.Rules {
		if r.Kind != pdomain.RequireApproval || r.Approval == nil || !s.inEnv(r.Environments) ||
			!slices.ContainsFunc(r.Operations, func(p string) bool {
				return slices.ContainsFunc(reached, func(o string) bool { return matches(p, o) })
			}) {
			continue
		}
		rules = append(rules, r.ID)
		role := r.Approval.Role
		independent := r.Approval.Independent || role == string(td.RoleCodeReviewer) || role == string(td.RoleReleaseApprover)
		if (r.Approval.Window || role == string(td.RoleReleaseApprover)) && s.windows == 0 {
			missing = append(missing, r.ID+" (a release window: no change window exists)")
			continue
		}
		people, err := q.DeciderCandidates(ctx, dbq.DeciderCandidatesParams{
			OrgID: s.org, Roles: []string{role}, BusinessUnitID: s.row.BusinessUnitID, TeamID: s.row.TeamID,
			EnvironmentID: s.row.EnvironmentID, Lim: 50,
		})
		if err != nil {
			return Check{}, err
		}
		eligible := slices.ContainsFunc(people, func(p dbq.DeciderCandidatesRow) bool {
			owner := (s.row.OwnerUserID != nil && *s.row.OwnerUserID == p.UserID) ||
				(s.row.BackupOwnerUserID != nil && *s.row.BackupOwnerUserID == p.UserID)
			return !independent || !owner
		})
		if !eligible {
			missing = append(missing, r.ID+" (role "+role+")")
		}
	}
	switch {
	case len(missing) > 0:
		return Check{Name: CheckApprovals, Detail: clip("no eligible approver for " + strings.Join(missing, ", "))}, nil
	case len(rules) == 0:
		return Check{Name: CheckApprovals, Passed: true, Detail: "the published policy holds nothing of it or its consequences for approval"}, nil
	}
	return Check{Name: CheckApprovals, Passed: true, Detail: clip("an eligible approver for " + strings.Join(rules, ", "))}, nil
}

func declared(fb string) Check {
	if !slices.Contains(FailureBehaviors, fb) {
		return Check{Name: CheckFailureBehavior, Detail: "declare FAIL_CLOSED, QUEUE or DEGRADE_READ_ONLY"}
	}
	return Check{Name: CheckFailureBehavior, Passed: true, Detail: "declared " + fb}
}
