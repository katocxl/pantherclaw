// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package assurance

import (
	"context"
	"slices"
	"strconv"

	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	exapp "github.com/katocxl/pantherclaw/internal/exposure/app"
	exdomain "github.com/katocxl/pantherclaw/internal/exposure/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Pre-enable inspection (D59, F710; Team): per consequential step, what it
// may do to the world and how the platform would know.

// Verification methods.
const (
	VerifyVerifier       = "VERIFIER"
	VerifyReconciliation = "RECONCILIATION"
	VerifyNone           = "NONE"
)

// InspectedOperation is one operation a step may perform.
type InspectedOperation struct {
	Operation     string
	EffectKinds   []string
	Reversibility string
	Consequences  []string
	// Coverage by ceiling agent id.
	Coverage     map[string]string
	Approvals    []string
	Verification string
}

// InspectedStep is one step of the version.
type InspectedStep struct {
	ID         string
	Kind       string
	Effectful  bool
	Operations []InspectedOperation
	Scopes     []string
}

// Inspection is a version's inspection.
type Inspection struct {
	Steps []InspectedStep
	Notes []string
	// Paths are a v2 version's paths; every step of any path is in Steps.
	Paths []InspectedPath
}

// InspectedPath is one path of a v2 version and its terminal's outcome.
type InspectedPath struct {
	Nodes   []string
	Outcome string
}

// InspectVersion inspects a version (D59).
func (s *Service) InspectVersion(ctx context.Context, versionID ids.UUID) (Inspection, error) {
	c, err := caller(ctx, td.PermAutomationRead)
	if err != nil {
		return Inspection{}, err
	}
	if err := s.edition(ctx, false); err != nil {
		return Inspection{}, err
	}
	var out Inspection
	err = s.Pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		_, def, err := version(ctx, dbq.New(tx), c.Org, versionID)
		if err != nil {
			return err
		}
		l, err := exapp.Load(ctx, tx)
		if err != nil {
			return err
		}
		out = Inspect(def, l.Inputs)
		return hideCoverage(ctx, c, dbq.New(tx), &out)
	}, db.ReadOnly())
	return out, err
}

// Inspect builds the inspection from the loaded inputs: a launch_run's
// operations are the connections' operations its grant (or else the
// ceiling) allows; other kinds act through the platform within their
// declared scopes.
func Inspect(def *autodomain.Definition, in exdomain.Inputs) Inspection {
	var out Inspection
	scopes := map[string][]string{}
	for _, p := range def.Authority.Platform {
		scopes[p.Step] = p.Scopes
	}
	for _, c := range in.Connections {
		if !c.Known && c.State != "RETIRED" {
			out.Notes = append(out.Notes, "connection "+c.Name+": its package cannot be read; its operations are not listed")
		}
	}
	for _, s := range def.Do {
		spec := autodomain.Catalog[s.Step]
		st := InspectedStep{ID: s.ID, Kind: s.Step, Effectful: spec.Effectful, Scopes: scopes[s.Step]}
		if s.Step == autodomain.KindLaunchRun && def.Authority.Ceiling != nil {
			st.Operations = launchOperations(def.Authority.Ceiling, launchOps(s), in)
		}
		if st.Effectful || len(st.Operations) > 0 {
			out.Steps = append(out.Steps, st)
		}
	}
	if def.IsV2() {
		f := def.Flow()
		paths, _ := f.Paths(autodomain.MaxPaths)
		for _, p := range paths {
			ip := InspectedPath{Nodes: p}
			if n := f.Node(p[len(p)-1]); n != nil {
				ip.Outcome = string(n.Outcome)
			}
			out.Paths = append(out.Paths, ip)
		}
	}
	return out
}

// launchOps is the operations a launch_run's grant narrows to, or nil.
func launchOps(s autodomain.StepSpec) *gdomain.Ops {
	w, err := s.DecodeWith()
	if err != nil {
		return nil
	}
	if lw, ok := w.(*autodomain.LaunchRunWith); ok {
		return lw.Grant.Operations
	}
	return nil
}

func launchOperations(ce *autodomain.Ceiling, narrow *gdomain.Ops, in exdomain.Inputs) []InspectedOperation {
	byName := map[string]*InspectedOperation{}
	var names []string
	for _, c := range in.Connections {
		if c.State == "RETIRED" || !c.Known {
			continue
		}
		for _, op := range c.Operations {
			if (ce.Bounds.Operations != nil && !ce.Bounds.Operations.Matches(op.Name)) || (narrow != nil && !narrow.Matches(op.Name)) {
				continue
			}
			x, ok := byName[op.Name]
			if !ok {
				x = &InspectedOperation{
					Operation: op.Name, EffectKinds: op.Effects, Reversibility: reversibility(op.Reversibility),
					Consequences: op.Consequences, Coverage: map[string]string{}, Verification: verification(op),
				}
				for _, r := range ce.Requirements {
					if r.Operations.Matches(op.Name) {
						x.Approvals = append(x.Approvals, requirementText(r))
					}
				}
				for _, rule := range in.Policy.Rules {
					if (rule.Kind == "REQUIRE_APPROVAL" || rule.Kind == "REQUIRE_STEP_UP") &&
						slices.ContainsFunc(rule.Operations, func(p string) bool { return patternMatches(p, op.Name) }) {
						x.Approvals = append(x.Approvals, "policy "+rule.Kind+" "+rule.ID)
					}
				}
				byName[op.Name] = x
				names = append(names, op.Name)
			}
			for _, a := range ce.Agents {
				cov, ok := in.Coverage[exdomain.CoverageKey{Agent: a.UUID(), Connection: c.ID, Operation: op.Name}]
				if !ok {
					cov = exdomain.CoverageUnknown
				}
				// The weakest path's coverage is what a bypass meets.
				if cur, seen := x.Coverage[a.String()]; !seen || cov.Rank() < exdomain.Coverage(cur).Rank() {
					x.Coverage[a.String()] = string(cov)
				}
			}
		}
	}
	slices.Sort(names)
	out := make([]InspectedOperation, 0, len(names))
	for _, n := range names {
		out = append(out, *byName[n])
	}
	return out
}

func reversibility(r defs.Reversibility) string {
	switch r {
	case defs.Reversible:
		return "REVERSIBLE"
	case defs.Compensatable:
		return "COMPENSABLE"
	case defs.Irreversible:
		return "IRREVERSIBLE"
	}
	return "UNKNOWN"
}

func verification(op exdomain.Operation) string {
	switch {
	case op.Verified:
		return VerifyVerifier
	case op.Reconciled:
		return VerifyReconciliation
	}
	return VerifyNone
}

// hideCoverage leaves out the coverage of agents outside the caller's
// exposure.read scope, as the previews do (D94 S9).
func hideCoverage(ctx context.Context, c tenancy.Caller, q *dbq.Queries, in *Inspection) error {
	seen, hidden := map[string]bool{}, map[string]bool{}
	for _, st := range in.Steps {
		for _, op := range st.Operations {
			for a := range op.Coverage {
				if !seen[a] {
					seen[a] = true
					ok, err := agentsVisible(ctx, c, q, []string{a})
					if err != nil {
						return err
					}
					hidden[a] = !ok
				}
				if hidden[a] {
					delete(op.Coverage, a)
				}
			}
		}
	}
	n := 0
	for _, h := range hidden {
		if h {
			n++
		}
	}
	if n > 0 {
		in.Notes = append(in.Notes, "coverage of "+strconv.Itoa(n)+" ceiling agents outside your exposure.read scope is not shown")
	}
	return nil
}
