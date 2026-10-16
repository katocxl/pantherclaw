// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"slices"
	"strings"
	"time"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Change kinds of the automation domain (D7).
const (
	KindEnable  = "ENABLE"
	KindRollout = "ROLLOUT"
)

// Void reasons of enabling requests.
const (
	VoidUntested          = "UNTESTED"
	VoidRolloutUnverified = "ROLLOUT_UNVERIFIED"
	VoidReviewDate        = "REVIEW_DATE"
	VoidPrincipal         = "PRINCIPAL_NOT_CONFIRMED"
	VoidState             = "STATE_CHANGED"
)

// enableContent is exactly what an enabling applies; its SHA-256 is the
// request's content digest, so a confirmation never carries over to other
// content (HR-272).
type enableContent struct {
	Automation   string   `json:"automation"`
	Version      string   `json:"version"`
	Digest       string   `json:"digest"`
	Rollout      string   `json:"rollout"`
	CohortAgents []string `json:"cohort_agents"`
	ReviewBy     string   `json:"review_by"`
}

func (c enableContent) digest() ([32]byte, error) {
	b, err := json.Marshal(c, json.Deterministic(true))
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// enableSummary is what the confirmers see and sign (with the content
// digest).
type enableSummary struct {
	enableContent
	Name                 string              `json:"name"`
	Number               int32               `json:"number"`
	Kind                 string              `json:"kind"`
	Summary              string              `json:"summary"`
	CeilingAgents        []string            `json:"ceiling_agents"`
	Operations           []string            `json:"operations"`
	ConfirmerPermissions map[string][]string `json:"confirmer_permissions"`
	Principal            string              `json:"principal"`
}

func strs(xs []ids.UUID) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, x.String())
	}
	slices.Sort(out)
	return out
}

func contentOf(a dbq.PcAutomation, v dbq.PcAutomationVersion, d *autodomain.Definition, rollout autodomain.Rollout, cohort []ids.UUID) enableContent {
	return enableContent{
		Automation: a.ID.String(), Version: v.ID.String(), Digest: hex.EncodeToString(v.Digest), Rollout: string(rollout),
		CohortAgents: strs(cohort), ReviewBy: reviewText(d),
	}
}

func reviewText(d *autodomain.Definition) string {
	b, _ := d.ReviewBy.MarshalText()
	return string(b)
}

// RegisterChanges registers the automation change kinds with the
// change-request service (called by server wiring).
func (s *Service) RegisterChanges() {
	h := changes.Handler{
		Permission: td.PermAutomationRead, Required: s.required, Eligible: s.eligible, Apply: s.apply,
	}
	s.Changes.Register(changes.DomainAutomation, KindEnable, h)
	s.Changes.Register(changes.DomainAutomation, KindRollout, h)
}

func summaryOf(r changes.Request) (enableSummary, error) {
	var out enableSummary
	err := json.Unmarshal(r.Summary, &out)
	return out, err
}

// requestDefinition loads the version a request names.
func requestDefinition(ctx context.Context, q *dbq.Queries, r changes.Request) (enableSummary, dbq.PcAutomationVersion, *autodomain.Definition, error) {
	sum, err := summaryOf(r)
	if err != nil {
		return sum, dbq.PcAutomationVersion{}, nil, err
	}
	vid, err := ids.ParseUUID(sum.Version)
	if err != nil {
		return sum, dbq.PcAutomationVersion{}, nil, err
	}
	v, err := loadVersion(ctx, q, r.Org, vid, false)
	if err != nil {
		return sum, v, nil, err
	}
	d, err := definitionOf(v)
	return sum, v, d, err
}

// required: SHADOW needs one person; COHORT and FULL need two when the
// org has at least two eligible people now, else one (D7).
func (s *Service) required(ctx context.Context, tx db.TenantTx, r changes.Request) (int, error) {
	q := dbq.New(tx)
	sum, _, d, err := requestDefinition(ctx, q, r)
	if err != nil {
		return 0, err
	}
	if sum.Rollout == string(autodomain.RolloutShadow) {
		return 1, nil
	}
	people, err := q.OrgUsersWithRoles(ctx, r.Org, rolesWith(td.PermAutomationPublish))
	if err != nil {
		return 0, err
	}
	scopes := d.RequiredConfirmerPermissions()
	n := 0
	for _, p := range people {
		ok, _, err := s.qualifies(ctx, tx.Pgx(), q, r.Org, p, scopes, d.CeilingAgents())
		if err != nil {
			return 0, err
		}
		if ok {
			n++
		}
	}
	if n >= 2 {
		return 2, nil
	}
	return 1, nil
}

// eligible: an active person holding automation.publish and every
// confirmer permission of the version's kinds at every scope it touches,
// not compromised (D7, HR-272).
func (s *Service) eligible(ctx context.Context, tx db.TenantTx, r changes.Request, user ids.UUID) (bool, string, error) {
	q := dbq.New(tx)
	_, _, d, err := requestDefinition(ctx, q, r)
	if err != nil {
		return false, "", err
	}
	return s.qualifies(ctx, tx.Pgx(), q, r.Org, user, d.RequiredConfirmerPermissions(), d.CeilingAgents())
}

// apply enables the version or widens its rollout, in the confirming
// transaction (D7, D54): every apply creates a fresh authority row.
func (s *Service) apply(ctx context.Context, tx db.TenantTx, r changes.Request, confirmers []ids.UUID) error {
	q := dbq.New(tx)
	sum, v, d, err := requestDefinition(ctx, q, r)
	if err != nil {
		return err
	}
	a, err := loadAutomation(ctx, q, r.Org, v.AutomationID, true)
	if err != nil {
		return err
	}
	rollout := autodomain.Rollout(sum.Rollout)
	cohort := make([]ids.UUID, 0, len(sum.CohortAgents))
	for _, x := range sum.CohortAgents {
		id, err := ids.ParseUUID(x)
		if err != nil {
			return err
		}
		cohort = append(cohort, id)
	}
	cur, err := contentOf(a, v, d, rollout, cohort).digest()
	if err != nil {
		return err
	}
	if !bytes.Equal(cur[:], r.ContentDigest[:]) || a.State == string(autodomain.StateRetired) {
		return &changes.VoidError{Reason: VoidContentChanged}
	}
	switch r.Kind {
	case KindEnable:
		if !slices.Contains([]string{"VALIDATED", "TESTED"}, v.State) {
			return &changes.VoidError{Reason: VoidState}
		}
	case KindRollout:
		if a.EnabledVersionID == nil || *a.EnabledVersionID != v.ID || a.Rollout == nil ||
			autodomain.Rollout(*a.Rollout).Rank() >= rollout.Rank() {
			return &changes.VoidError{Reason: VoidState}
		}
		if rollout == autodomain.RolloutFull {
			if ok, err := s.rolloutVerified(ctx, tx, a.ID, v.ID); err != nil {
				return err
			} else if !ok {
				return &changes.VoidError{Reason: VoidRolloutUnverified}
			}
		}
	}
	if rollout != autodomain.RolloutShadow {
		if ok, err := s.tested(ctx, tx, v); err != nil {
			return err
		} else if !ok {
			return &changes.VoidError{Reason: VoidUntested}
		}
	}
	if u, ok := d.Authority.PrincipalUser(); ok && !slices.Contains(confirmers, u.UUID()) {
		return &changes.VoidError{Reason: VoidPrincipal}
	}
	now, err := dbNow(ctx, q)
	if err != nil {
		return err
	}
	reviewBy := d.ReviewBy.End()
	if limit := now.Add(autodomain.MaxReviewWindow - time.Minute); reviewBy.After(limit) {
		reviewBy = limit
	}
	if !reviewBy.After(now) {
		return &changes.VoidError{Reason: VoidReviewDate}
	}
	ended, err := q.EndActiveAutomationCeilings(ctx, dbq.EndActiveAutomationCeilingsParams{
		State: string(autodomain.CeilingSuperseded), OrgID: r.Org, AutomationID: a.ID,
	})
	if err != nil {
		return err
	}
	ceiling := ids.NewV7()
	if err := q.InsertAutomationCeiling(ctx, dbq.InsertAutomationCeilingParams{
		OrgID: r.Org, ID: ceiling, AutomationID: a.ID, VersionID: v.ID, Digest: v.Digest, ApprovedBy: confirmers,
		ChangeRequestID: r.ID, ReviewBy: reviewBy,
	}); err != nil {
		return err
	}
	if r.Kind == KindEnable {
		rid := r.ID
		if err := oneRow(q.PublishAutomationVersion(ctx, dbq.PublishAutomationVersionParams{
			ChangeRequestID: &rid, OrgID: r.Org, ID: v.ID, Digest: v.Digest,
		})); err != nil {
			return &changes.VoidError{Reason: VoidState}
		}
		if _, err := q.SupersedeAutomationVersions(ctx, r.Org, a.ID, v.ID); err != nil {
			return err
		}
	}
	vid, ro := v.ID, string(rollout)
	var cohortAgents []ids.UUID
	if rollout == autodomain.RolloutCohort {
		cohortAgents = cohort
	}
	if err := oneRow(q.EnableAutomation(ctx, dbq.EnableAutomationParams{
		VersionID: &vid, Rollout: &ro, CohortAgents: cohortAgents, OrgID: r.Org, ID: a.ID,
	})); err != nil {
		return err
	}
	if a.State != string(autodomain.StatePaused) && s.Triggers != nil {
		if err := s.Triggers.Activate(ctx, tx.Pgx(), a.ID, v.ID); err != nil {
			return err
		}
	}
	name := "automation.enabled"
	if r.Kind == KindRollout {
		name = "automation.rollout_widened"
	}
	caller, err := tapp.CallerFrom(ctx)
	if err != nil {
		return err
	}
	return record(ctx, tx, caller.Actor(), name, a.ID, map[string]string{
		"version": v.ID.String(), "rollout": ro, "ceiling": ceiling.String(), "approvers": strings.Join(strs(confirmers), ","),
		"change_request": r.ID.String(), "review_by": reviewBy.UTC().Format(time.RFC3339), "superseded": itoa(len(ended)),
	})
}

// tested asks the TestGate (assurance, D34); without one nothing is
// tested.
func (s *Service) tested(ctx context.Context, tx db.TenantTx, v dbq.PcAutomationVersion) (bool, error) {
	if s.TestGate == nil {
		return false, nil
	}
	_, ok, err := s.TestGate.Passed(ctx, tx.Pgx(), v.ID, v.Digest)
	return ok, err
}

func (s *Service) rolloutVerified(ctx context.Context, tx db.TenantTx, automation, version ids.UUID) (bool, error) {
	if s.Rollout == nil {
		return false, nil
	}
	ok, _, err := s.Rollout.Verified(ctx, tx.Pgx(), automation, version)
	return ok, err
}

// Enabled is a request to enable a version, waiting for confirmation.
type Enabled struct {
	Request  changes.Request
	Required int
}

// RequestEnable asks for a version to be enabled at a rollout stage, or for
// the enabled version to widen its rollout (D7). SHADOW needs a VALIDATED
// or TESTED version; COHORT and FULL need passing tests (HR-287); widening
// to FULL needs a verified cohort stage. COHORT agents are a subset of the
// ceiling's agents (D55).
func (s *Service) RequestEnable(ctx context.Context, version ids.UUID, rollout autodomain.Rollout, cohortAgents []ids.UUID, cohortID ids.UUID) (Enabled, error) {
	c, err := manager(ctx)
	if err != nil {
		return Enabled{}, err
	}
	if err := s.edition(ctx); err != nil {
		return Enabled{}, err
	}
	switch {
	case !cohortID.IsZero():
		return Enabled{}, ErrCohortUnavail
	case !rollout.Valid():
		return Enabled{}, ErrRollout
	case (rollout == autodomain.RolloutCohort) != (len(cohortAgents) > 0):
		return Enabled{}, ErrRollout
	}
	var out Enabled
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		v, err := loadVersion(ctx, q, c.Org, version, false)
		if err != nil {
			return err
		}
		a, err := loadAutomation(ctx, q, c.Org, v.AutomationID, true)
		if err != nil {
			return err
		}
		if a.State == string(autodomain.StateRetired) {
			return ErrState
		}
		d, err := definitionOf(v)
		if err != nil {
			return err
		}
		kind := KindEnable
		if a.EnabledVersionID != nil && *a.EnabledVersionID == v.ID {
			kind = KindRollout
			if a.Rollout == nil || autodomain.Rollout(*a.Rollout).Rank() >= rollout.Rank() {
				return ErrRollout // narrowing is NarrowRollout's
			}
			if rollout == autodomain.RolloutFull {
				if ok, err := s.rolloutVerified(ctx, tx, a.ID, v.ID); err != nil {
					return err
				} else if !ok {
					return ErrRolloutUnverified
				}
			}
		} else if !slices.Contains([]string{"VALIDATED", "TESTED"}, v.State) {
			return ErrVersionState
		}
		agents := d.CeilingAgents()
		for _, x := range cohortAgents {
			if !slices.Contains(agents, x) {
				return ErrRollout
			}
		}
		if rollout != autodomain.RolloutShadow {
			if ok, err := s.tested(ctx, tx, v); err != nil {
				return err
			} else if !ok {
				return ErrUntested
			}
		}
		content := contentOf(a, v, d, rollout, cohortAgents)
		digest, err := content.digest()
		if err != nil {
			return err
		}
		scopes := d.RequiredConfirmerPermissions()
		ops := []string{}
		if d.Authority.Ceiling != nil && d.Authority.Ceiling.Bounds.Operations != nil {
			ops = *d.Authority.Ceiling.Bounds.Operations
		}
		summary := enableSummary{
			enableContent: content, Name: a.Name, Number: v.Number, Kind: kind, Summary: v.Summary,
			CeilingAgents: strs(agents), Operations: ops, Principal: d.Authority.Principal,
			ConfirmerPermissions: map[string][]string{
				"org":                 append([]string{string(td.PermAutomationPublish)}, scopes.Org...),
				"every_ceiling_agent": scopes.AgentPaths,
			},
		}
		req, err := s.Changes.RequestTx(ctx, tx, c, changes.Requested{
			Domain: changes.DomainAutomation, Kind: kind, Subject: a.ID, Content: digest, Summary: summary,
		})
		if err != nil {
			return err
		}
		out = Enabled{Request: req, Required: req.Required}
		return record(ctx, tx, c.Actor(), "automation.enable_requested", a.ID, map[string]string{
			"version": v.ID.String(), "rollout": string(rollout), "kind": kind, "change_request": req.ID.String(),
		})
	})
	return out, err
}

// NarrowRollout narrows the enabled version's rollout at once (D5):
// FULL to COHORT to SHADOW, or COHORT to a smaller cohort. Narrowing needs
// one person; the authority row stays.
func (s *Service) NarrowRollout(ctx context.Context, automation ids.UUID, rollout autodomain.Rollout, cohortAgents []ids.UUID) (Automation, error) {
	c, err := manager(ctx)
	if err != nil {
		return Automation{}, err
	}
	if !rollout.Valid() || (rollout == autodomain.RolloutCohort) != (len(cohortAgents) > 0) {
		return Automation{}, ErrRollout
	}
	var out Automation
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		a, err := loadAutomation(ctx, q, c.Org, automation, true)
		if err != nil {
			return err
		}
		if a.Rollout == nil || a.EnabledVersionID == nil {
			return ErrState
		}
		cur := autodomain.Rollout(*a.Rollout)
		switch {
		case rollout.Rank() > cur.Rank():
			return ErrRollout
		case rollout == cur && rollout != autodomain.RolloutCohort:
			return ErrRollout
		case rollout == autodomain.RolloutCohort && cur == autodomain.RolloutCohort:
			for _, x := range cohortAgents {
				if !slices.Contains(a.CohortAgents, x) {
					return ErrRollout
				}
			}
		case rollout == autodomain.RolloutCohort:
			v, err := loadVersion(ctx, q, c.Org, *a.EnabledVersionID, false)
			if err != nil {
				return err
			}
			d, err := definitionOf(v)
			if err != nil {
				return err
			}
			for _, x := range cohortAgents {
				if !slices.Contains(d.CeilingAgents(), x) {
					return ErrRollout
				}
			}
		}
		ro := string(rollout)
		var cohort []ids.UUID
		if rollout == autodomain.RolloutCohort {
			cohort = cohortAgents
		}
		if err := oneRow(q.NarrowAutomationRollout(ctx, dbq.NarrowAutomationRolloutParams{
			Rollout: &ro, CohortAgents: cohort, OrgID: c.Org, ID: a.ID, FromRollout: a.Rollout,
		})); err != nil {
			return err
		}
		if s.Changes != nil {
			if _, err := s.Changes.Void(ctx, tx, c, changes.DomainAutomation, a.ID, VoidState); err != nil {
				return err
			}
		}
		r, err := loadAutomation(ctx, q, c.Org, a.ID, false)
		if err != nil {
			return err
		}
		out = automationView(r)
		return record(ctx, tx, c.Actor(), "automation.rollout_narrowed", a.ID, map[string]string{
			"from": string(cur), "to": ro, "cohort_agents": itoa(len(cohort)),
		})
	})
	return out, err
}
