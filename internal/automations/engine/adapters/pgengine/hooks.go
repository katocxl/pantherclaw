// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// hooks implement engine.Hooks against the database.
type hooks struct{ e *Engine }

// Revalidate implements engine.Hooks (HR-273, D14): the kill switch, the
// automation and its enabled version, the owner, the execution identity
// and its containment, the ceiling and its approvers, the represented
// person and the edition. The first failing check names the reason.
func (h hooks) Revalidate(ctx context.Context, tx pgx.Tx, x *engine.Exec) (string, error) {
	q := dbq.New(tx)
	var principalUser *ids.UUID
	if x.View.Principal.Kind == "user" {
		principalUser = &x.View.Principal.ID
	}
	var ceiling *ids.UUID
	if !x.View.Ceiling.IsZero() {
		ceiling = &x.View.Ceiling
	}
	s, err := q.AutomationAuthorityState(ctx, dbq.AutomationAuthorityStateParams{
		OrgID: x.Org, AutomationID: x.Automation, CeilingID: ceiling, PrincipalUserID: principalUser,
	})
	if err != nil {
		return "", err
	}
	if s.KillSwitch {
		return autodomain.ReasonKillSwitch, nil
	}
	if s.EnabledVersionID == nil || *s.EnabledVersionID != x.Version {
		return autodomain.ReasonAuthorityChanged, nil
	}
	switch autodomain.State(s.State) {
	case autodomain.StateActive:
	case autodomain.StatePaused:
		if r := pausedReason(s.PauseReason); r != "" {
			return r, nil
		}
	case autodomain.StateDraft, autodomain.StateRetired:
		return autodomain.ReasonAuthorityChanged, nil
	default:
		return autodomain.ReasonAuthorityChanged, nil
	}
	if s.OwnerState != "ACTIVE" {
		return autodomain.ReasonOwnerInactive, nil
	}
	if s.IdentityState != "ACTIVE" {
		return autodomain.ReasonAuthorityChanged, nil
	}
	if s.IdentityContained {
		if h.e.Pauser != nil {
			if _, err := h.e.Pauser.Pause(ctx, tx, x.Org, autodomain.PauseSelector{Automations: []ids.UUID{x.Automation}},
				autodomain.PauseContained); err != nil {
				return "", err
			}
		}
		return autodomain.ReasonContained, nil
	}
	if s.PrincipalState != "ACTIVE" {
		return autodomain.ReasonAuthorityChanged, nil
	}
	if ceiling != nil {
		approvers := s.CeilingApprovers
		if s.CeilingState == string(autodomain.CeilingSuperseded) {
			// A rollout of the same version superseded the ceiling the
			// execution started under: it goes on under the current one
			// (D54, D84 E3).
			c, err := q.GetActiveAutomationCeiling(ctx, x.Org, x.Automation)
			if err != nil && !db.IsNoRows(err) {
				return "", err
			}
			if err != nil || c.VersionID != x.Version {
				return autodomain.ReasonCeilingVoid, nil
			}
			ceiling, approvers = &c.ID, c.ApprovedBy
			s.CeilingState, s.CeilingInReview = c.State, c.InReview
			x.View.Ceiling, x.View.Confirmers = c.ID, c.ApprovedBy
		}
		if s.CeilingState != string(autodomain.CeilingActive) || !s.CeilingInReview {
			return autodomain.ReasonCeilingVoid, nil
		}
		if h.e.Ceilings != nil {
			ok, _, err := h.e.Ceilings.Check(ctx, tx, autodomain.CeilingCheck{
				Org: x.Org, Automation: x.Automation, Ceiling: *ceiling, Approvers: approvers,
				Agents: ceilingAgents(x.Def), Kinds: kindsOf(x.Def),
			})
			if err != nil {
				return "", err
			}
			if !ok {
				return autodomain.ReasonCeilingVoid, nil
			}
		}
	}
	if h.e.Editions != nil {
		ents, err := h.e.Editions.Current(ctx)
		if err != nil {
			return "", err
		}
		if !ents.Automations() || needsBusiness(x.Def) && !ents.AutomationPlaybooks() {
			return autodomain.ReasonAuthorityChanged, nil
		}
	}
	return "", nil
}

// pausedReason maps a pause to the execution reason that stops it; a
// pause that only stops new executions (USER, COVERAGE_RECOVERY, LOOP)
// lets active ones go on (HR-283).
func pausedReason(r *string) string {
	if r == nil {
		return autodomain.ReasonAuthorityChanged
	}
	switch autodomain.PauseReason(*r) {
	case autodomain.PauseUser, autodomain.PauseCoverageRecovery, autodomain.PauseLoop:
		return ""
	case autodomain.PauseKillSwitch:
		return autodomain.ReasonKillSwitch
	case autodomain.PauseContained:
		return autodomain.ReasonContained
	case autodomain.PauseCeilingVoid, autodomain.PauseCeilingExpired:
		return autodomain.ReasonCeilingVoid
	case autodomain.PauseOwnerInactive:
		return autodomain.ReasonOwnerInactive
	case autodomain.PauseAuthorityRevoked, autodomain.PauseCompromisedPublisher:
	}
	return autodomain.ReasonAuthorityChanged
}

func ceilingAgents(d *autodomain.Definition) []ids.UUID {
	if d.Authority.Ceiling == nil {
		return nil
	}
	out := make([]ids.UUID, 0, len(d.Authority.Ceiling.Agents))
	for _, a := range d.Authority.Ceiling.Agents {
		out = append(out, a.UUID())
	}
	return out
}

// kindsOf lists the step kinds a version uses, compensation included.
func kindsOf(d *autodomain.Definition) []string {
	var out []string
	add := func(specs []autodomain.StepSpec) {
		for _, s := range specs {
			if !slices.Contains(out, s.Step) {
				out = append(out, s.Step)
			}
		}
	}
	add(d.Do)
	if d.IfFails != nil {
		add(d.IfFails.Compensate)
	}
	slices.Sort(out)
	return out
}

func needsBusiness(d *autodomain.Definition) bool {
	return slices.ContainsFunc(kindsOf(d), func(k string) bool {
		return autodomain.Catalog[k].Edition == autodomain.EditionBusiness
	})
}

// Quarantined implements engine.Hooks (D59).
func (h hooks) Quarantined(ctx context.Context, tx pgx.Tx, x *engine.Exec) (bool, error) {
	c := x.Def.Authority.Ceiling
	if c == nil || c.Bounds.Operations == nil {
		return false, nil
	}
	exact, prefixes := []string{}, []string{}
	for _, op := range *c.Bounds.Operations {
		if p, ok := strings.CutSuffix(op, "*"); ok {
			prefixes = append(prefixes, p)
		} else {
			exact = append(exact, op)
		}
	}
	return dbq.New(tx).OperationsQuarantined(ctx, x.Org, exact, prefixes)
}

// escalationWindow is how long the owner has to act on an owned failure.
const escalationWindow = 24 * time.Hour

// Escalate implements engine.Hooks: an owned failure for the automation's
// owner (D38).
func (h hooks) Escalate(ctx context.Context, tx pgx.Tx, x *engine.Exec, kind, step, reason string) error {
	if h.e.Failures == nil {
		return nil
	}
	summary := "Automation " + x.View.AutomationName + " execution " + x.ID.String()
	if step != "" {
		summary += " step " + step
	}
	if reason != "" {
		summary += ": " + reason
	}
	key := kind + ":" + x.ID.String()
	if step != "" {
		key += ":" + step
	}
	if reason == autodomain.ReasonCeilingVoid && !x.View.Ceiling.IsZero() {
		// One failure per ceiling, not per execution (D84 E4).
		key = kind + ":ceiling:" + x.View.Ceiling.String()
	}
	_, err := h.e.Failures.Report(ctx, tx, reflexdomain.Failure{
		Org: x.Org, Kind: kind, Summary: summary,
		NextStep: "Open the execution in the automation inspector and decide what to do with its unresolved work.",
		Scope: []reflexdomain.Subject{
			{Type: reflexdomain.SubjectAutomation, ID: x.Automation.String()},
			{Type: reflexdomain.SubjectAutomationExecution, ID: x.ID.String()},
		},
		Owner:    &reflexdomain.Subject{Type: reflexdomain.SubjectUser, ID: x.View.Owner.String()},
		Deadline: time.Now().Add(escalationWindow).UTC(), DedupeKey: key,
	})
	return err
}

// Cleanup implements engine.Hooks (D24).
func (h hooks) Cleanup(ctx context.Context, tx pgx.Tx, x *engine.Exec) ([]reflexdomain.EvidenceRef, error) {
	if h.e.Cleaner == nil {
		return nil, nil
	}
	return h.e.Cleaner.Cleanup(ctx, tx, x)
}

// Reconciled implements engine.Hooks (D27).
func (h hooks) Reconciled(ctx context.Context, tx pgx.Tx, x *engine.Exec) (bool, bool, error) {
	if h.e.Reconciler == nil {
		return false, false, nil
	}
	return h.e.Reconciler.Reconciled(ctx, tx, x)
}
