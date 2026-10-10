// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the approval rules of G0 M5 part 2 (Pass): the
// requirements a hold carries and how they merge, the binding an approval
// signs (PAP-1 §8, HR-030), the request state machine with expiry at use
// (HR-039, HR-171), and who may decide (HR-035, HR-036, HR-170). It does no
// I/O: the application layer reads the records and calls these functions,
// both when a person responds and again when the approval is used.
package domain

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"time"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Requirement kinds.
const (
	KindApproval = "approval"
	KindStepUp   = "step_up"
	// KindRestore is a restoration's one requirement (decision 11): a
	// person holding agent.restore on the agent's scope path, other than
	// the requester. Only the server creates it; no grant or policy may
	// name it.
	KindRestore = "restore"
)

// RestoreRequirement is the requirement of every restoration.
var RestoreRequirement = Requirement{Kind: KindRestore, Count: 1, Sources: []Source{}}

// RestoreRole reports whether role decides restorations: it holds
// agent.restore (Security Admin and Responder).
func RestoreRole(role string) bool {
	r, ok := td.LookupRole(td.RoleName(role))
	return ok && r.Has(td.PermAgentRestore)
}

// Step-up subjects and the only method (decision 4).
const (
	SubjectLauncher  = "launcher"
	SubjectPrincipal = "principal"
	MethodWebAuthn   = "webauthn"
)

// Bounds of requirements and deadlines (decisions 6 and 7).
const (
	// MaxApprovers is the largest count a grant may ask for; policies allow 2.
	MaxApprovers = 5
	// MaxRequirements bounds the merged list (the schema allows 16).
	MaxRequirements = 16
	// MinDeadline and MaxDeadline bound a deadline a requirement sets.
	MinDeadline = 5 * time.Minute
	MaxDeadline = 7 * 24 * time.Hour
	// DefaultDeadline applies when no requirement sets one.
	DefaultDeadline = time.Hour
	// DefaultConsumeWindow is how long an approved request may wait for its
	// resubmission, never past the deadline.
	DefaultConsumeWindow = 15 * time.Minute
)

// ErrRequirementInvalid is returned for a requirement that no one could
// satisfy correctly: an unknown approval role, a count out of range, a
// step-up of another subject or method, or a deadline out of bounds. A
// stored requirement that fails gives CANNOT_AUTHORIZE (REQUIREMENT_INVALID),
// never a hold (decision 2, design decision 1).
var ErrRequirementInvalid = pcerr.New(pcerr.InvalidArgument, ReasonRequirementInvalid, "the approval requirement is invalid")

// Source says where a requirement comes from: a grant or guardrail level
// with its revision, or a policy rule, and the reason it gives.
type Source struct {
	Level  string `json:"level"`
	Reason string `json:"reason"`
}

// Input is one requirement as the pipeline found it, before merging.
type Input struct {
	Kind        string
	Role        string
	Count       int
	Independent bool
	Subject     string
	Method      string
	// Deadline is the hold deadline the requirement sets (0: none).
	Deadline time.Duration
	Source   Source
}

// Requirement is one merged requirement of a request.
type Requirement struct {
	Kind        string   `json:"kind"`
	Role        string   `json:"role,omitzero"`
	Count       int      `json:"count,omitzero"`
	Independent bool     `json:"independent,omitzero"`
	Subject     string   `json:"subject,omitzero"`
	Method      string   `json:"method,omitzero"`
	Sources     []Source `json:"sources"`
}

// Needed is how many distinct people must respond.
func (r Requirement) Needed() int {
	if r.Kind == KindStepUp {
		return 1
	}
	return r.Count
}

// BoundRequirement is what the binding covers of a requirement: who must
// act, not where the requirement came from (that is in the decision basis).
type BoundRequirement struct {
	Kind        string `json:"kind"`
	Role        string `json:"role,omitzero"`
	Count       int    `json:"count,omitzero"`
	Independent bool   `json:"independent,omitzero"`
	Subject     string `json:"subject,omitzero"`
	Method      string `json:"method,omitzero"`
}

// Bound returns the bound part of a merged list.
func Bound(rs []Requirement) []BoundRequirement {
	out := make([]BoundRequirement, 0, len(rs))
	for _, r := range rs {
		out = append(out, BoundRequirement{
			Kind: r.Kind, Role: r.Role, Count: r.Count, Independent: r.Independent, Subject: r.Subject, Method: r.Method,
		})
	}
	return out
}

// ApprovalRole reports whether an approval requirement may name role: a
// default role that holds approval.respond (decision 2; today only
// "approver"). Eligibility then comes from where the role is bound.
func ApprovalRole(role string) bool {
	r, ok := td.LookupRole(td.RoleName(role))
	return ok && r.Has(td.PermApprovalRespond)
}

// Validate checks one input requirement (design decision 1).
func (in Input) Validate() error {
	switch in.Kind {
	case KindApproval:
		if !ApprovalRole(in.Role) {
			return fmt.Errorf("%w: role %q is not a default role that holds approval.respond", ErrRequirementInvalid, in.Role)
		}
		if in.Count < 1 || in.Count > MaxApprovers {
			return fmt.Errorf("%w: an approval needs 1..%d approvers", ErrRequirementInvalid, MaxApprovers)
		}
	case KindStepUp:
		if in.Subject != SubjectLauncher && in.Subject != SubjectPrincipal {
			return fmt.Errorf("%w: a step-up names the launcher or the principal", ErrRequirementInvalid)
		}
		if in.Method != MethodWebAuthn {
			return fmt.Errorf("%w: a step-up uses webauthn", ErrRequirementInvalid)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrRequirementInvalid, in.Kind)
	}
	if in.Deadline != 0 && (in.Deadline < MinDeadline || in.Deadline > MaxDeadline) {
		return fmt.Errorf("%w: a deadline is between %s and %s", ErrRequirementInvalid, MinDeadline, MaxDeadline)
	}
	return nil
}

// Merge validates and merges the inputs deterministically (design decision
// 14): approvals naming the same role become one, with the larger count and
// independence if either asks; different roles stay separate; step-ups are
// kept per subject. Approvals come first by role, then step-ups by subject.
// The deadline is the shortest any input sets, or 0 when none sets one.
func Merge(ins []Input) ([]Requirement, time.Duration, error) {
	if len(ins) == 0 {
		return nil, 0, errors.New("approvals: no requirements to merge")
	}
	var out []Requirement
	var deadline time.Duration
	for _, in := range ins {
		if err := in.Validate(); err != nil {
			return nil, 0, err
		}
		if in.Deadline != 0 && (deadline == 0 || in.Deadline < deadline) {
			deadline = in.Deadline
		}
		i := slices.IndexFunc(out, func(r Requirement) bool {
			return r.Kind == in.Kind && r.Role == in.Role && r.Subject == in.Subject
		})
		if i < 0 {
			out = append(out, Requirement{Kind: in.Kind, Role: in.Role, Subject: in.Subject, Method: in.Method})
			i = len(out) - 1
		}
		r := &out[i]
		if in.Kind == KindApproval {
			r.Count = max(r.Count, in.Count)
			r.Independent = r.Independent || in.Independent
		}
		if !slices.Contains(r.Sources, in.Source) {
			r.Sources = append(r.Sources, in.Source)
		}
	}
	if len(out) > MaxRequirements {
		return nil, 0, fmt.Errorf("%w: more than %d distinct requirements", ErrRequirementInvalid, MaxRequirements)
	}
	for i := range out {
		slices.SortFunc(out[i].Sources, func(a, b Source) int {
			return cmp.Or(cmp.Compare(a.Level, b.Level), cmp.Compare(a.Reason, b.Reason))
		})
	}
	slices.SortFunc(out, func(a, b Requirement) int {
		return cmp.Or(cmp.Compare(kindRank(a.Kind), kindRank(b.Kind)), cmp.Compare(a.Role, b.Role), cmp.Compare(a.Subject, b.Subject))
	})
	return out, deadline, nil
}

func kindRank(k string) int {
	if k == KindApproval {
		return 0
	}
	return 1
}

// Deadline returns a new hold's deadline: now plus the requirements'
// deadline, or the org's default when they set none, in whole seconds
// because the binding covers it (PAP-1 §8).
func Deadline(now time.Time, required, orgDefault time.Duration) time.Time {
	d := orgDefault
	if d <= 0 {
		d = DefaultDeadline
	}
	if required > 0 {
		d = required
	}
	return now.UTC().Add(d).Truncate(time.Second)
}

// ConsumeBy returns when an approval given at approvedAt must be used: the
// consume window later, but never after the deadline (decision 6).
func ConsumeBy(approvedAt, deadline time.Time, window time.Duration) time.Time {
	if window <= 0 {
		window = DefaultConsumeWindow
	}
	if by := approvedAt.Add(window); by.Before(deadline) {
		return by
	}
	return deadline
}
