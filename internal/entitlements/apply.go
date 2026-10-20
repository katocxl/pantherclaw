// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package entitlements

import (
	"context"
	"encoding/json/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Snapshot is the plan the billing extension reports for an org at one
// event (extension.PlanSnapshot).
type Snapshot struct {
	PlanID    string
	Edition   string
	Status    Status
	Limits    Limits
	Features  []string
	PeriodEnd time.Time
	EventID   string
	EventAt   time.Time
}

// Plan writer errors.
var (
	// ErrInvalidSnapshot: a snapshot no plan may have, including COMP and
	// DEV, which never come from billing (HR-361).
	ErrInvalidSnapshot = pcerr.New(pcerr.InvalidArgument, "INVALID_PLAN", "invalid plan snapshot")
	// ErrNotExternal: plans are written by billing only in billing mode
	// external.
	ErrNotExternal = pcerr.New(pcerr.FailedPrecondition, "BILLING_MODE", "plans come from billing only in billing mode external")
	// ErrUnknownOrg: no active org has the id.
	ErrUnknownOrg = pcerr.New(pcerr.NotFound, "ORG_NOT_FOUND", "unknown organization")
)

// billingActor is who the billing extension's changes are recorded as.
var billingActor = evdomain.Actor{Type: "system", ID: "billing-extension"}

func (s Snapshot) check() error {
	switch {
	case !s.Status.Billing():
		return ErrInvalidSnapshot
	case s.Edition == EditionDevelopment, s.Edition != "" && !ValidEdition(s.Edition):
		return ErrInvalidSnapshot
	case s.PlanID != "" && s.Edition == "":
		// A status-only event (no plan id) may leave the edition out (D70).
		return ErrInvalidSnapshot
	case !planIDPattern(s.PlanID):
		return ErrInvalidSnapshot
	case s.EventID == "" || len(s.EventID) > 128 || s.EventAt.IsZero():
		return ErrInvalidSnapshot
	case !s.Limits.valid() || len(s.Features) > 128:
		return ErrInvalidSnapshot
	}
	for _, f := range s.Features {
		if f == "" || len(f) > 64 {
			return ErrInvalidSnapshot
		}
	}
	return nil
}

func planIDPattern(id string) bool {
	if id == "" {
		return true
	}
	if len(id) > 64 || !isLowerAlnum(id[0]) {
		return false
	}
	for i := range len(id) {
		c := id[i]
		if !isLowerAlnum(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isLowerAlnum(c byte) bool { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') }

// ApplyPlan records the plan the billing extension reports for org
// (HR-354, HR-355). It is idempotent by event id: a replayed event changes
// nothing. An event strictly older than the newest one applied is recorded
// and ignored; an equal timestamp applies. While an operator's comp plan is
// in force, billing events are recorded and do not replace it. Every change
// is recorded in the org's evidence ledger.
func (s *Service) ApplyPlan(ctx context.Context, org ids.OrgID, snap Snapshot) error {
	if s.mode != ModeExternal {
		return ErrNotExternal
	}
	if org.IsZero() || org == ids.PlatformOrg {
		return ErrUnknownOrg
	}
	if err := snap.check(); err != nil {
		return err
	}
	features := slices.Clone(snap.Features)
	if features == nil {
		features = []string{}
	}
	slices.Sort(features)
	features = slices.Compact(features)
	limits, err := json.Marshal(snap.Limits)
	if err != nil {
		return err
	}
	at := snap.EventAt.UTC()
	return s.pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		state, err := q.OrgState(ctx, org)
		if db.IsNoRows(err) || (err == nil && state != "ACTIVE") {
			return ErrUnknownOrg
		} else if err != nil {
			return err
		}
		cur, err := q.LockOrgEntitlements(ctx, org)
		found := err == nil
		if err != nil && !db.IsNoRows(err) {
			return err
		}
		// A status-only event (no plan id) keeps the plan, edition, limits
		// and features in force and changes only the status and period
		// (D70); without a plan in force it needs an edition.
		planID, edition := snap.PlanID, snap.Edition
		if planID == "" {
			switch {
			case found:
				planID, edition, limits, features = cur.PlanID, cur.Edition, cur.Limits, cur.Features
			case edition == "":
				return ErrInvalidSnapshot
			}
		}
		kind := "APPLIED"
		switch {
		case found && cur.Source == string(SourceComp) && cur.Status == string(StatusComp) &&
			cur.CompUntil != nil && s.clock.Now().Before(*cur.CompUntil):
			kind = "IGNORED_COMP"
		case found && cur.LastEventAt != nil && at.Before(*cur.LastEventAt):
			kind = "IGNORED_STALE"
		}
		n, err := q.InsertEntitlementEvent(ctx, dbq.InsertEntitlementEventParams{
			OrgID: org, EventID: snap.EventID, Kind: kind, Status: string(snap.Status), EventAt: at,
		})
		if err != nil {
			return err
		}
		if n == 0 {
			return nil // replayed event: already recorded (HR-355)
		}
		details := map[string]string{
			"event_id": snap.EventID, "event_at": at.Format(time.RFC3339Nano), "status": string(snap.Status),
			"plan_id": planID, "edition": edition,
		}
		if kind != "APPLIED" {
			_, err := audit.Record(ctx, tx, audit.Event{
				Name: "billing.plan_event_ignored", Actor: billingActor, Outcome: audit.Denied, ReasonCode: kind,
				Object: &audit.Object{Type: "org", ID: org.String()}, Details: details,
			})
			return err
		}
		var periodEnd *time.Time
		if !snap.PeriodEnd.IsZero() {
			pe := snap.PeriodEnd.UTC()
			periodEnd = &pe
			details["period_end"] = pe.Format(time.RFC3339)
		}
		version, err := q.PutBillingPlan(ctx, dbq.PutBillingPlanParams{
			OrgID: org, PlanID: planID, Edition: edition, Limits: limits, Features: features,
			Status: string(snap.Status), PeriodEnd: periodEnd, EventAt: &at,
		})
		if err != nil {
			return err
		}
		details["version"] = strconv.FormatInt(version, 10)
		if f := strings.Join(features, ","); len(f) <= 500 {
			details["features"] = f
		} else {
			details["features"] = f[:500]
		}
		if found {
			details["previous_status"] = cur.Status
		}
		_, err = audit.Record(ctx, tx, audit.Event{
			Name: "billing.plan_applied", Actor: billingActor, Outcome: audit.Success,
			Object: &audit.Object{Type: "org", ID: org.String()}, Details: details,
		})
		return err
	})
}
