// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package coveragerpc serves CoverageService over Connect (G0 M9 track A).
// Handlers only translate: authentication, the coarse permission check and
// protovalidate have run before a handler is called, and the use cases
// check the caller's permission over each agent. RPCs not yet built answer
// Unimplemented.
package coveragerpc

import (
	"context"

	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/katocxl/pantherclaw/internal/coverage/domain"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
)

// Handler serves CoverageService.
type Handler struct {
	pantherclawv1connect.UnimplementedCoverageServiceHandler
	freshness domain.Freshness
}

// New returns the CoverageService handler.
func New(f domain.Freshness) *Handler { return &Handler{freshness: f} }

var states = map[domain.State]pantherclawv1.CoverageState{
	domain.Unknown:     pantherclawv1.CoverageState_COVERAGE_STATE_UNKNOWN,
	domain.ObserveOnly: pantherclawv1.CoverageState_COVERAGE_STATE_OBSERVE_ONLY,
	domain.Partial:     pantherclawv1.CoverageState_COVERAGE_STATE_PARTIAL,
	domain.Enforced:    pantherclawv1.CoverageState_COVERAGE_STATE_ENFORCED,
}

// GetFreshnessContract implements CoverageServiceHandler (F440).
func (h *Handler) GetFreshnessContract(context.Context, *pantherclawv1.GetFreshnessContractRequest) (*pantherclawv1.GetFreshnessContractResponse, error) {
	out := &pantherclawv1.GetFreshnessContractResponse{
		EnforcedTtl:   durationpb.New(h.freshness.EnforcedTTL),
		ReassessEvery: durationpb.New(h.freshness.ReassessEvery),
		StaleState:    states[domain.StaleState],
	}
	for _, k := range domain.InvalidationKinds {
		if !k.Invalidates() {
			continue
		}
		out.InvalidationKinds = append(out.InvalidationKinds, string(k))
	}
	return out, nil
}
