// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pgengine

import (
	"context"
	"encoding/json/v2"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/automations/steps"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Launch errors (D26).
var (
	ErrInstanceInactive = pcerr.New(pcerr.PermissionDenied, "INSTANCE_NOT_ADMITTED", "only an admitted instance claims launches")
	ErrLaunchNotYours   = pcerr.New(pcerr.NotFound, "LAUNCH_NOT_FOUND", "no launch claimed by this instance")
	ErrLaunchReport     = pcerr.New(pcerr.InvalidArgument, "LAUNCH_REPORT_INVALID",
		"a launch report names declared calls with known statuses, at most 20, and a note of at most 500 characters")
)

// Launch outcomes and call statuses (D26, D33, D83).
var (
	launchOutcomes = []string{"SUCCEEDED", "FAILED", "PARTIAL"}
	callStatuses   = []string{"OK", "DENIED", "HELD", "FAILED", "UNKNOWN", "SKIPPED"}
)

// ClaimedLaunch is what an agent gets when it claims a launch: no secret,
// only the run to bind with its own key and the version's declared calls.
type ClaimedLaunch struct {
	ID         ids.UUID
	Run        ids.UUID
	TaskRef    string
	RunParams  map[string]string
	Calls      []steps.StoredCall
	CompleteBy time.Time
}

// CallResult is the outcome of one declared call (D26).
type CallResult struct {
	CallIndex   int    `json:"call_index"`
	Status      string `json:"status"`
	Transaction string `json:"transaction_id,omitzero"`
	ErrorCode   string `json:"error_code,omitzero"`
}

// launchReport is a completed launch's stored report; the note is
// UNTRUSTED agent text.
type launchReport struct {
	Results []CallResult `json:"results"`
	Note    string       `json:"note,omitzero"`
}

func instanceActor(instance ids.UUID) evdomain.Actor {
	return evdomain.Actor{Type: "instance", ID: instance.String()}
}

// ClaimLaunch claims the oldest pending launch for the calling instance's
// agent (D26, HR-285). It returns false when none is pending.
func (e *Engine) ClaimLaunch(ctx context.Context, org ids.OrgID, instance ids.UUID) (ClaimedLaunch, bool, error) {
	var out ClaimedLaunch
	found := false
	err := e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		inst, err := q.InstanceAgent(ctx, org, instance)
		if db.IsNoRows(err) || err == nil && inst.State != "ADMITTED" {
			return ErrInstanceInactive
		} else if err != nil {
			return err
		}
		r, err := q.ClaimAutomationLaunch(ctx, &instance, org, inst.AgentID)
		if db.IsNoRows(err) {
			return nil
		} else if err != nil {
			return err
		}
		out = ClaimedLaunch{ID: r.ID, Run: r.RunID, TaskRef: r.TaskRef, CompleteBy: r.CompleteBy}
		if err := json.Unmarshal(r.RunParams, &out.RunParams); err != nil {
			return err
		}
		if err := json.Unmarshal(r.Calls, &out.Calls); err != nil {
			return err
		}
		found = true
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "automation.launch_claimed", Actor: instanceActor(instance), Outcome: audit.Success,
			Object:  &audit.Object{Type: "automation_launch", ID: r.ID.String()},
			Details: map[string]string{"execution": r.ExecutionID.String(), "run": r.RunID.String()},
		}); err != nil {
			return err
		}
		return e.enqueue(ctx, tx.Pgx(), org, r.ExecutionID)
	})
	return out, found, err
}

// CompleteLaunch records a claimed launch's outcome; only the claiming
// instance may, once (D26). The execution is woken to read it.
func (e *Engine) CompleteLaunch(ctx context.Context, org ids.OrgID, instance, launch ids.UUID, outcome string,
	results []CallResult, note string,
) error {
	if !slices.Contains(launchOutcomes, outcome) || len(results) > 20 || utf8.RuneCountInString(note) > 500 ||
		!utf8.ValidString(note) {
		return ErrLaunchReport
	}
	for _, r := range results {
		if r.CallIndex < 0 || r.CallIndex >= 10 || !slices.Contains(callStatuses, r.Status) {
			return ErrLaunchReport
		}
	}
	report, err := json.Marshal(launchReport{Results: results, Note: note}, json.Deterministic(true))
	if err != nil {
		return err
	}
	return e.Pool.InTenantTx(ctx, org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		r, err := q.CompleteAutomationLaunch(ctx, dbq.CompleteAutomationLaunchParams{
			Outcome: &outcome, Report: report, OrgID: org, ID: launch, InstanceID: &instance,
		})
		if db.IsNoRows(err) {
			return ErrLaunchNotYours
		} else if err != nil {
			return err
		}
		if _, err := audit.Record(ctx, tx, audit.Event{
			Name: "automation.launch_completed", Actor: instanceActor(instance), Outcome: audit.Success,
			Object:  &audit.Object{Type: "automation_launch", ID: launch.String()},
			Details: map[string]string{"execution": r.ExecutionID.String(), "run": r.RunID.String(), "outcome": outcome},
		}); err != nil {
			return err
		}
		return e.enqueue(ctx, tx.Pgx(), org, r.ExecutionID)
	})
}
