// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package recording

import (
	"fmt"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	papp "github.com/katocxl/pantherclaw/internal/policy/app"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
)

// Compile compiles b, the bundle the recorded reference names, as the
// evaluation compiled it: with the same fact types, CEL limits and cost
// budget, so its rules evaluate the same way.
func (p *Policy) Compile(b *pdomain.Bundle) (*pipeline.Policy, error) {
	if b == nil || b.ID != p.Bundle || b.Version != p.Version {
		return nil, fmt.Errorf("recording: the bundle is not %s", p.Ref)
	}
	c, err := p.engine().Compile(b, nil)
	if err != nil {
		return nil, err
	}
	return &pipeline.Policy{Compiled: c, Version: p.Ref, Budget: p.Budget}, nil
}

// Proposed compiles another bundle (a draft or a later version, F505) the
// way the recorded policy was compiled. With no recorded policy, catalog
// gives the fact types and the defaults the limits and budget.
func (p *Policy) Proposed(b *pdomain.Bundle, catalog map[string]fdomain.Type) (*pipeline.Policy, error) {
	e, budget := &papp.Engine{Limits: celenv.DefaultLimits, Facts: catalog}, uint64(papp.DefaultBudget)
	if p != nil && !p.None && p.Err == "" {
		e, budget = p.engine(), p.Budget
	}
	c, err := e.Compile(b, nil)
	if err != nil {
		return nil, err
	}
	return &pipeline.Policy{Compiled: c, Version: fmt.Sprintf("%s@%d", b.ID, b.Version), Budget: budget}, nil
}

func (p *Policy) engine() *papp.Engine {
	facts := make(map[string]fdomain.Type, len(p.Catalog))
	for name, t := range p.Catalog {
		facts[name] = fdomain.Type(t)
	}
	return &papp.Engine{
		Limits: celenv.Limits{
			MaxExpressionBytes: p.Limits.MaxExpressionBytes, MaxCost: p.Limits.MaxCost,
			MaxComprehensionNesting: p.Limits.MaxComprehensionNesting, EstimatedCollectionSize: p.Limits.EstimatedCollectionSize,
		},
		Facts: facts,
	}
}
