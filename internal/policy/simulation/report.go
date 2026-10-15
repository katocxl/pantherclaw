// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package simulation

import (
	"fmt"
	"slices"
	"strings"
	"time"

	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Limits is the F192 text every report carries.
const Limits = "A simulation predicts decisions, not agent replanning or business outcomes: it replays recorded decisions on the " +
	"inputs they read, so a rule that needs a fact or read the original decision never made counts as unevaluable."

// Bounds of a report's groups: an operation or agent beyond them is
// counted under Other, so a report stays small (HR-237).
const (
	MaxGroups = 1000
	MaxRoles  = 100
	Other     = "other"
	// RoleStepUp and RoleOther name the burden of a step-up, and of a hold
	// no rule of the version names a role for.
	RoleStepUp = "step_up"
	RoleOther  = "other"
)

// Counts counts recorded decisions by category.
type Counts map[Category]int

// Total is the number of decisions counted.
func (c Counts) Total() int {
	n := 0
	for _, v := range c {
		n += v
	}
	return n
}

// Report is what a simulation found so far.
type Report struct {
	Counts      Counts
	ByOperation map[string]Counts
	ByAgent     map[string]Counts
	// HeldPerDay counts the decisions newly held by the day (UTC,
	// YYYY-MM-DD) they were recorded, and HeldByRole by the approver role
	// the version requires (the approval burden forecast).
	HeldPerDay map[string]int
	HeldByRole map[string]int
}

// NewReport returns an empty report.
func NewReport() Report {
	return Report{
		Counts: Counts{}, ByOperation: map[string]Counts{}, ByAgent: map[string]Counts{},
		HeldPerDay: map[string]int{}, HeldByRole: map[string]int{},
	}
}

func group(m map[string]Counts, key string, max int) Counts {
	if c, ok := m[key]; ok {
		return c
	}
	if len(m) >= max {
		key = Other
		if c, ok := m[key]; ok {
			return c
		}
	}
	m[key] = Counts{}
	return m[key]
}

func bump(m map[string]int, key string, max int) {
	if _, ok := m[key]; !ok && len(m) >= max {
		key = Other
	}
	m[key]++
}

// Add counts one evaluated decision.
func (r *Report) Add(o Result) {
	r.Counts[o.Category]++
	group(r.ByOperation, o.Operation, MaxGroups)[o.Category]++
	group(r.ByAgent, o.Agent.String(), MaxGroups)[o.Category]++
	if o.Category == NewlyHeld {
		bump(r.HeldPerDay, o.Recorded.UTC().Format(time.DateOnly), MaxGroups)
		bump(r.HeldByRole, o.Role, MaxRoles)
	}
}

// Notices flag what needs attention in a report.
func (s Simulation) Notices() []string {
	var out []string
	if n := s.Report.Counts[NewlyAllowed]; n > 0 {
		out = append(out, fmt.Sprintf("expanded exposure: %d recorded decision(s) would have been less strict under this version", n))
	}
	if n := s.Report.Counts[Unevaluable]; n > 0 {
		out = append(out, fmt.Sprintf("%d recorded decision(s) could not be evaluated: they do not reproduce, or the version needs inputs "+
			"they never read; their samples name why", n))
	}
	if s.State == Done && s.Evaluated >= s.Max {
		out = append(out, fmt.Sprintf("the cap of %d decisions was reached: older decisions of the window were not simulated", s.Max))
	}
	return out
}

// Result is one recorded decision evaluated under the version. It carries
// ids, decisions and reason codes, never an input value (HR-237).
type Result struct {
	Transaction ids.UUID
	Evaluation  int
	Agent       ids.UUID
	Operation   string
	Recorded    time.Time
	Category    Category
	Original    adomain.Decision
	OrigReason  string
	Proposed    adomain.Decision
	PropReason  string
	// Limitations are the codes that made it unevaluable.
	Limitations []string
	// Role is the approver role of a newly held decision.
	Role string
}

// Sample is a stored sample decision.
type Sample struct {
	Category    Category
	Transaction ids.UUID
	Evaluation  int
	Agent       ids.UUID
	Operation   string
	Original    string
	OrigReason  string
	Proposed    string
	PropReason  string
	Limitations []string
}

// SampleOf is the stored form of a result.
func SampleOf(r Result) Sample {
	return Sample{
		Category: r.Category, Transaction: r.Transaction, Evaluation: r.Evaluation, Agent: r.Agent, Operation: r.Operation,
		Original: string(r.Original), OrigReason: r.OrigReason, Proposed: string(r.Proposed), PropReason: r.PropReason,
		Limitations: r.Limitations,
	}
}

// heldRole is the approver role the version requires for a decision it
// holds: the decisive policy rule's approval role, step_up for a step-up,
// or other.
func heldRole(b *pdomain.Bundle, decision adomain.Decision, checklist []pipeline.Item) string {
	for _, it := range checklist {
		if !it.Decisive || !strings.HasPrefix(it.Level, "policy ") {
			continue
		}
		_, rest, ok := strings.Cut(it.Level, " rule ")
		if !ok {
			continue
		}
		id, _, _ := strings.Cut(rest, " ")
		if i := slices.IndexFunc(b.Rules, func(r pdomain.Rule) bool { return r.ID == id }); i >= 0 {
			if r := b.Rules[i]; r.Approval != nil && r.Approval.Role != "" {
				return r.Approval.Role
			} else if r.StepUp != nil {
				return RoleStepUp
			}
		}
	}
	if decision == adomain.RequireStepUp {
		return RoleStepUp
	}
	return RoleOther
}
