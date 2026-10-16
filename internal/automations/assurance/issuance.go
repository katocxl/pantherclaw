// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"errors"
	"slices"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	grantsapp "github.com/katocxl/pantherclaw/internal/grants/app"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Issuance previews (D94 S5, D84): a simulation's launch decisions run
// grants' own issuance with DryRun, as a SHADOW or TEST execution's do,
// against the automation's ACTIVE authority row for this version or, for a
// version without one, the version's declared ceiling. Each preview runs in
// its own transaction that always rolls back: the replay's transaction is
// READ ONLY, and a dry run's reservation needs a savepoint. Nothing is
// written (HR-288, T-127).

// Issuer is the grants use case that issues under an automation's ceiling
// (grants app IssueForAutomationTx).
type Issuer interface {
	IssueForAutomationTx(ctx context.Context, tx db.TenantTx, in grantsapp.AutomationIssue) (gdomain.Grant, error)
}

// IssueDecision is a launch_run step's dry-run issuance.
type IssueDecision struct {
	Refused bool
	Reason  string
}

// errPreviewRollback rolls a preview's transaction back.
var errPreviewRollback = errors.New("assurance: issuance preview rolled back")

// previewIssuance dry-runs each launch_run step's grant once; nil when no
// Issuer is wired (launch decisions then check the ceiling only,
// MissingIssuancePreview). A launch whose `with` the replay refuses itself
// (WITH_INVALID, OUTSIDE_CEILING) is not previewed.
func (s *Service) previewIssuance(ctx context.Context, org ids.OrgID, v dbq.AssuranceVersionRow, def *autodomain.Definition,
) (map[string]IssueDecision, error) {
	if s.Issuer == nil || def.Authority.Ceiling == nil {
		return nil, nil
	}
	var ceiling ids.UUID
	if err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		c, err := dbq.New(tx).AssuranceActiveCeiling(ctx, org, v.AutomationID)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		if c.VersionID == v.ID {
			ceiling = c.ID
		}
		return nil
	}, db.ReadOnly()); err != nil {
		return nil, err
	}
	out := map[string]IssueDecision{}
	for _, st := range def.Do {
		if st.Step != autodomain.KindLaunchRun {
			continue
		}
		in, ok := launchIssue(def.Authority.Ceiling, st)
		if !ok {
			continue
		}
		in.Org, in.Automation, in.Version, in.Ceiling, in.ServiceAccount = org, v.AutomationID, v.ID, ceiling, v.ServiceAccountID
		in.Principal = principalOf(def, v.ServiceAccountID)
		in.DryRun = true
		var issued error
		err := s.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
			_, issued = s.Issuer.IssueForAutomationTx(ctx, tx, in)
			return errPreviewRollback
		})
		if !errors.Is(err, errPreviewRollback) {
			return nil, err
		}
		switch {
		case issued == nil, errors.Is(issued, grantsapp.ErrUsageExceeded):
			// Today's caps say nothing of a past day: the replay counts
			// each day's grants against the ceiling's per-day cap itself.
			out[st.ID] = IssueDecision{}
		case fatal(issued):
			return nil, issued
		default:
			reason := pcerr.ReasonOf(issued)
			if reason == "" {
				reason = "REFUSED"
			}
			out[st.ID] = IssueDecision{Refused: true, Reason: reason}
		}
	}
	return out, nil
}

// fatal reports an error that is no refusal: the job retries.
func fatal(err error) bool {
	return slices.Contains([]pcerr.Code{pcerr.Internal, pcerr.Unavailable, pcerr.Canceled, pcerr.DeadlineExceeded, pcerr.Aborted},
		pcerr.CodeOf(err))
}

// launchIssue is the grant a launch_run asks for, as the step plans it
// (steps launch.go): the ceiling's bounds narrowed by the step's grant, the
// per-grant limits unless the step names its own, the per-grant TTL unless
// the step's is shorter. It is false for a `with` the step would refuse.
func launchIssue(c *autodomain.Ceiling, st autodomain.StepSpec) (grantsapp.AutomationIssue, bool) {
	w, err := st.DecodeWith()
	lw, ok := w.(*autodomain.LaunchRunWith)
	if err != nil || !ok {
		return grantsapp.AutomationIssue{}, false
	}
	ttl := c.PerGrant.TTL.D()
	if lw.TTL > 0 {
		if lw.TTL.D() > ttl {
			return grantsapp.AutomationIssue{}, false
		}
		ttl = lw.TTL.D()
	}
	bounds := c.Bounds
	g := lw.Grant
	if g.Operations != nil {
		bounds.Operations = g.Operations
	}
	if g.Targets != nil {
		bounds.Targets = g.Targets
	}
	if g.Accounts != nil {
		bounds.Accounts = g.Accounts
	}
	if g.Destinations != nil {
		bounds.Destinations = g.Destinations
	}
	if g.Params != nil {
		bounds.Params = g.Params
	}
	limits := c.PerGrant.Limits
	if g.Limits != nil {
		limits = *g.Limits
	}
	in := grantsapp.AutomationIssue{
		AgentID: lw.Agent.UUID(), TaskRef: lw.TaskRef, TTL: ttl, Bounds: bounds, Requirements: c.Requirements, Limits: limits,
	}
	if lw.Instance != nil {
		i := lw.Instance.UUID()
		in.InstanceID = &i
	}
	return in, true
}

// principalOf is the version's declared principal: a consenting confirmer,
// or the automation's own identity.
func principalOf(def *autodomain.Definition, serviceAccount ids.UUID) gdomain.Principal {
	if u, ok := def.Authority.PrincipalUser(); ok {
		return gdomain.Principal{Kind: gdomain.PrincipalUser, ID: u.UUID()}
	}
	return gdomain.Principal{Kind: gdomain.PrincipalServiceAccount, ID: serviceAccount}
}
