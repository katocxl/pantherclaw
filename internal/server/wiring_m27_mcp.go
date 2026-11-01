// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"slices"

	"connectrpc.com/connect/v2"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// errInvestigatorReads refuses the Investigator role outside its four reads.
var errInvestigatorReads = pcerr.New(pcerr.PermissionDenied, "INVESTIGATOR_READS_ONLY",
	"the Investigator role reads what happened, run timelines, search and breach radius, and nothing else")

// selfMCPInterceptors hold the Investigator role to selfMCPReads on the server,
// so a key taken from a SOC agent's host writes nothing whatever client it
// uses (G0 M27 D510, HR-655).
func selfMCPInterceptors(apiDeps) []connect.ServerInterceptor {
	g := &selfMCPGate{}
	return []connect.ServerInterceptor{g.intercept}
}

// selfMCPGate runs after authentication, with the caller in the context.
// Outside selfMCPReads the role does not count: the call goes on with the
// caller's other bindings, or is refused when those do not admit it.
type selfMCPGate struct{}

func (g *selfMCPGate) intercept(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		c, err := tapp.CallerFrom(ctx)
		if err != nil || !isInvestigator(c) {
			return next(ctx, spec, stream) // public, workload and gateway calls carry no caller here
		}
		if slices.Contains(selfMCPReads, spec.Procedure) {
			return next(ctx, spec, stream)
		}
		rest := withoutInvestigator(c)
		if !procedureAdmits(rest, spec.Procedure) {
			return errInvestigatorReads
		}
		return next(tapp.WithCaller(ctx, rest), spec, stream)
	}
}
