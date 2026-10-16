// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"crypto/sha256"
	"errors"
	"maps"
	"slices"
	"strconv"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// KindGate is the one requirement of an automation gate (G0 M11 part 2 D25,
// D25a, HR-281): Count people holding automation.approve at the org (a
// role among Roles when it lists any, a person among Users when it lists
// any), none of them in Exclude, each with a security key. Only the engine
// creates it; no grant or policy may name it.
const KindGate = "gate"

// GateSubject is the subject a gate binding names.
const GateSubject = "automation.gate"

// Why a person may not decide a gate.
const (
	IneligibleGateExcluded    = "GATE_EXCLUDED"
	IneligibleNotGateApprover = "NOT_A_GATE_APPROVER"
)

// GateRole reports whether role decides gates: it holds automation.approve.
func GateRole(role string) bool {
	r, ok := td.LookupRole(td.RoleName(role))
	return ok && r.Has(td.PermAutomationApprove)
}

// GateRequirement is a gate's requirement: n approvals by people with
// automation.approve, narrowed to roles and users when they are listed,
// never by the excluded people.
func GateRequirement(n int, roles []string, users, exclude []ids.UUID) Requirement {
	r := Requirement{Kind: KindGate, Count: n, Sources: []Source{{Level: "automation", Reason: "gate"}}}
	r.Roles = slices.Sorted(slices.Values(slices.Clone(roles)))
	r.Users = idStrings(users)
	r.Exclude = idStrings(exclude)
	return r
}

func idStrings(us []ids.UUID) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.String())
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// checkGate checks a gate's decider (HR-281): not excluded, listed when
// the gate lists people, holding a role with automation.approve at the org
// (one of the gate's roles when it lists roles; a self-granted one only
// after the self-grant delay; with two approvals, after the role and
// account cooldowns), with an active key.
func checkGate(r Requirement, p Person, c Context, cred ids.UUID) (bool, string) {
	u := p.UserID.String()
	if slices.Contains(r.Exclude, u) {
		return false, IneligibleGateExcluded
	}
	if len(r.Users) > 0 && !slices.Contains(r.Users, u) {
		return false, IneligibleNotGateApprover
	}
	cd := c.Cooldowns.AtLeastMinimum()
	multi := r.Count >= 2
	why := IneligibleNoRole
	held := slices.ContainsFunc(p.Bindings, func(b RoleBinding) bool {
		if !GateRole(b.Role) || len(r.Roles) > 0 && !slices.Contains(r.Roles, b.Role) {
			return false
		}
		age := c.Now.Sub(b.CreatedAt)
		switch {
		case b.SelfGranted && age < cd.SelfGrantDelay:
			why = IneligibleSelfGrant
			return false
		case multi && age < cd.RoleAge:
			if why == IneligibleNoRole {
				why = IneligibleRoleCooldown
			}
			return false
		}
		return true
	})
	if !held {
		return false, why
	}
	if multi && c.Now.Sub(p.JoinedAt) < cd.AccountAge {
		return false, IneligibleAccountTooNew
	}
	var minAge time.Duration
	if multi {
		minAge = cd.CredentialAge
	}
	return credentialOK(p, cred, minAge, c.Now)
}

// GateInput is what a gate's display is rendered from.
type GateInput struct {
	Automation     ids.UUID
	AutomationName string
	Execution      ids.UUID
	StepID         string
	Attempt        int
	// Params are the trigger's typed parameters as text (shown, and bound
	// by their digest).
	Params       map[string]string
	Summary      string
	Requirements []Requirement
	Deadline     time.Time
}

// RenderGate renders a gate's display (D25). The summary may carry
// trigger parameters, so it is untrusted text.
func RenderGate(in GateInput) Display {
	out := Display{
		V: DisplayVersion, Kind: "automation_gate",
		Title: "Approve step " + in.StepID + " of automation " + in.AutomationName,
		Consequence: Consequence{
			Operation: GateSubject, Target: actionir.Target{Type: "automation_execution", ID: in.Execution.String()},
			Effects: []string{"the execution continues past step " + in.StepID + " with the parameters shown"},
		},
		Fields: []Field{
			{Name: "automation", Value: in.Automation.String()},
			{Name: "execution", Value: in.Execution.String()},
			{Name: "step", Value: in.StepID},
			{Name: "attempt", Value: strconv.Itoa(in.Attempt)},
		},
		Facts: []FactLine{}, Deadline: in.Deadline.UTC().Format(time.RFC3339),
	}
	out.finish(in.Requirements, nil, nil)
	items := []Untrusted{Clean("summary", in.Summary, 0)}
	for _, k := range slices.Sorted(maps.Keys(in.Params)) {
		items = append(items, Clean("param:"+Clean("", k, 64).Text, in.Params[k], 0))
	}
	out.Untrusted = untrustedBlock(items)
	return out
}

func sum256(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// GateBinding is what a gate's approvers sign (HR-281): this execution,
// this step and attempt, the parameters' digest, the summary, who may
// decide and the deadline. An approval never carries to another execution
// or changed parameters.
type GateBinding struct {
	V                    int                `json:"v"`
	Subject              string             `json:"subject"`
	Automation           string             `json:"automation"`
	Execution            string             `json:"execution"`
	Step                 string             `json:"step"`
	Attempt              int                `json:"attempt"`
	ParamsDigest         string             `json:"params_digest"`
	SummaryHash          string             `json:"summary_hash"`
	ApproverRequirements []BoundRequirement `json:"approver_requirements"`
	// Who may decide beyond the bound requirement: the roles and people it
	// is narrowed to and the people it excludes.
	Roles       []string `json:"roles"`
	Users       []string `json:"users"`
	Exclude     []string `json:"exclude"`
	ExpiresAt   string   `json:"expires_at"`
	DisplayHash string   `json:"display_hash"`
}

// GateParts are the values a gate binding is built from.
type GateParts struct {
	Automation   ids.UUID
	Execution    ids.UUID
	StepID       string
	Attempt      int
	ParamsDigest []byte
	Summary      string
	Requirements []Requirement
	ExpiresAt    time.Time
	DisplayHash  [32]byte
}

// Binding computes the gate binding.
func (p GateParts) Binding() (Binding, error) {
	if p.Automation.IsZero() || p.Execution.IsZero() || p.StepID == "" || p.Attempt < 1 || len(p.ParamsDigest) != 32 ||
		len(p.Requirements) == 0 {
		return Binding{}, errors.New("approvals: an incomplete gate binding")
	}
	b := GateBinding{
		V: BindingVersion, Subject: GateSubject, Automation: p.Automation.String(), Execution: p.Execution.String(),
		Step: p.StepID, Attempt: p.Attempt, ParamsDigest: B64(p.ParamsDigest), SummaryHash: B64(sum256(p.Summary)),
		ApproverRequirements: Bound(p.Requirements), DisplayHash: B64(p.DisplayHash[:]),
		Roles: []string{}, Users: []string{}, Exclude: []string{},
	}
	for _, r := range p.Requirements {
		b.Roles = append(b.Roles, r.Roles...)
		b.Users = append(b.Users, r.Users...)
		b.Exclude = append(b.Exclude, r.Exclude...)
	}
	var err error
	if b.ExpiresAt, err = expires(p.ExpiresAt); err != nil {
		return Binding{}, err
	}
	return canonical(b)
}
