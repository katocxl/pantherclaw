// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package grantsrpc

import (
	"slices"

	"github.com/katocxl/pantherclaw/internal/actionir"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/grants/domain"
)

// Flows decodes a request's flow allowances (G0 M16 D75); issuance
// validates them. None allows no flow.
func Flows(in []*pantherclawv1.FlowAllowance) []domain.FlowAllowance {
	if len(in) == 0 {
		return nil
	}
	out := make([]domain.FlowAllowance, 0, len(in))
	for _, f := range in {
		a := domain.FlowAllowance{Classes: slices.Clone(f.GetClasses())}
		for _, d := range f.GetDestinations() {
			a.Destinations = append(a.Destinations, actionir.Destination{Kind: d.GetKind(), ID: d.GetId()})
		}
		out = append(out, a)
	}
	return out
}

// FlowsProto renders a grant's flow allowances.
func FlowsProto(flows []domain.FlowAllowance) []*pantherclawv1.FlowAllowance {
	out := make([]*pantherclawv1.FlowAllowance, 0, len(flows))
	for _, f := range flows {
		p := &pantherclawv1.FlowAllowance{Classes: slices.Clone(f.Classes)}
		for _, d := range f.Destinations {
			p.Destinations = append(p.Destinations, &pantherclawv1.FlowDestination{Kind: d.Kind, Id: d.ID})
		}
		out = append(out, p)
	}
	return out
}
