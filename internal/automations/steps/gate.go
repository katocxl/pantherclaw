// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package steps

import (
	"context"
	"crypto/sha256"
	"encoding/json/v2"
	"slices"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/engine"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Gate bounds (D25).
const (
	MaxGateDeadline = 72 * time.Hour
	MaxGateSummary  = 1000
)

// gate asks eligible people to approve this execution's step with a
// security key (D25, HR-281): an AUTOMATION_GATE approval request bound to
// the execution, the step, the attempt and the parameters' digest. It is
// DONE once approved, FAILED GATE_DECLINED or GATE_EXPIRED otherwise, and
// FAILED GATE_NO_APPROVER when nobody may decide it.
type gate struct{ d Deps }

func (*gate) Kind() string { return autodomain.KindGate }

func (s *gate) request(sc autodomain.StepContext) (GateRequest, bool) {
	w, ok := sc.With.(*autodomain.GateWith)
	if !ok || w.Deadline <= 0 || w.Deadline.D() > MaxGateDeadline || len([]rune(w.Summary)) > MaxGateSummary {
		return GateRequest{}, false
	}
	n := w.MinApprovals
	if n == 0 {
		n = 1
	}
	if n < 1 || n > 2 {
		return GateRequest{}, false
	}
	exclude := w.Exclude
	if len(exclude) == 0 {
		exclude = []string{autodomain.ExcludeOwner}
	}
	ex := sc.Execution
	var out []ids.UUID
	for _, e := range exclude {
		switch e {
		case autodomain.ExcludeOwner:
			out = append(out, ex.Owner)
		case autodomain.ExcludeConfirmers:
			out = append(out, ex.Confirmers...)
		case autodomain.ExcludePrincipal:
			if ex.Principal.Kind == gdomain.PrincipalUser {
				out = append(out, ex.Principal.ID)
			}
		default:
			return GateRequest{}, false
		}
	}
	slices.SortFunc(out, compareUUID)
	out = slices.Compact(out)
	users := make([]ids.UUID, 0, len(w.Approvers.Users))
	for _, u := range w.Approvers.Users {
		users = append(users, u.UUID())
	}
	return GateRequest{
		Org: sc.Org, Automation: ex.Automation, Execution: ex.ID, StepID: sc.Spec.ID, Attempt: sc.Attempt,
		ParamsDigest: ParamsDigest(sc.Params), Summary: w.Summary, Roles: w.Approvers.Roles, Users: users, Exclude: out,
		MinApprovals: n, Deadline: w.Deadline.D(),
	}, true
}

func compareUUID(a, b ids.UUID) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// ParamsDigest is SHA-256 of the canonical JSON of the trigger's typed
// parameters: a gate's approval binds it (HR-281).
func ParamsDigest(p map[string]autodomain.Value) []byte {
	if p == nil {
		p = map[string]autodomain.Value{}
	}
	b, err := json.Marshal(p, json.Deterministic(true))
	if err != nil {
		b = nil
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

func (s *gate) Run(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Gates == nil {
		return unwired()
	}
	in, ok := s.request(sc)
	if !ok {
		return failed(ReasonBadWith)
	}
	id, eligible, err := s.d.Gates.RequestGate(ctx, tx, in)
	if err != nil {
		if r, ok := refusal(err); ok {
			return failed(r)
		}
		return autodomain.StepResult{}, err
	}
	if eligible == 0 || id.IsZero() {
		return failed(autodomain.ReasonGateNoApprover)
	}
	return autodomain.StepResult{
		State: autodomain.StepWaiting, Effect: autodomain.EffectNone,
		Output: map[string]string{
			OutRequest: id.String(), "eligible": strconv.Itoa(eligible),
			"deadline": rfc(sc.Now.Add(in.Deadline)),
		},
		WakeAt: sc.Now.Add(engine.PollInterval),
	}, nil
}

func (s *gate) Poll(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	if s.d.Gates == nil {
		return unwired()
	}
	o := own(sc)
	id, ok := parseID(o[OutRequest])
	if !ok {
		return failed(ReasonBadWith)
	}
	st, err := s.d.Gates.GateStatus(ctx, tx, sc.Org, id)
	if err != nil {
		return autodomain.StepResult{}, err
	}
	refs := []reflexdomain.EvidenceRef{ref(RefApprovalRequest, id)}
	switch st.State {
	case "APPROVED", "CONSUMED":
		in, ok := s.request(sc)
		if !ok || len(st.Approvers) < in.MinApprovals {
			return failed(ReasonGateEnded)
		}
		if st.State == "APPROVED" {
			// The approval is used once, by this step (HR-281).
			if err := s.d.Gates.ConsumeGate(ctx, tx, sc.Org, id); err != nil {
				return autodomain.StepResult{}, err
			}
		}
		out := clone(o)
		out["approvals"] = strconv.Itoa(len(st.Approvers))
		return autodomain.StepResult{State: autodomain.StepDone, Effect: autodomain.EffectNone, Output: out, Refs: refs}, nil
	case "DECLINED":
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: autodomain.ReasonGateDeclined,
			Effect: autodomain.EffectNone, Output: o, Refs: refs,
		}, nil
	case "EXPIRED":
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: autodomain.ReasonGateExpired,
			Effect: autodomain.EffectNone, Output: o, Refs: refs,
		}, nil
	case "INVALIDATED", "SUPERSEDED":
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: ReasonGateEnded,
			Effect: autodomain.EffectNone, Output: o, Refs: refs,
		}, nil
	}
	deadline, ok := parseRFC(o["deadline"])
	if ok && !sc.Now.Before(deadline) {
		// The gate's own deadline ends it, whatever the request says.
		if err := s.d.Gates.EndGate(ctx, tx, sc.Org, id, autodomain.ReasonGateExpired); err != nil {
			return autodomain.StepResult{}, err
		}
		return autodomain.StepResult{
			State: autodomain.StepFailed, Reason: autodomain.ReasonGateExpired, Effect: autodomain.EffectNone,
			Output: o, Refs: refs,
		}, nil
	}
	wake := sc.Now.Add(engine.PollInterval)
	if ok && deadline.Before(wake) {
		wake = deadline
	}
	return autodomain.StepResult{
		State: autodomain.StepWaiting, Effect: autodomain.EffectNone, Output: o, WakeAt: wake,
	}, nil
}

// Preview counts who could decide the gate and asks nobody (HR-288).
func (s *gate) Preview(ctx context.Context, tx pgx.Tx, sc autodomain.StepContext) (autodomain.StepResult, error) {
	in, ok := s.request(sc)
	if !ok {
		return failed(ReasonBadWith)
	}
	out := map[string]string{"shadow": "true"}
	if s.d.Gates != nil {
		n, err := s.d.Gates.EligibleGate(ctx, tx, in)
		if err != nil {
			return autodomain.StepResult{}, err
		}
		out["eligible"] = strconv.Itoa(n)
		if n == 0 {
			out["decision"] = "REFUSED"
			return autodomain.StepResult{State: autodomain.StepFailed, Reason: autodomain.ReasonGateNoApprover, Output: out}, nil
		}
	}
	return shadowed(out)
}
