// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/rpcauth"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/partners"
	"github.com/katocxl/pantherclaw/internal/partners/partnersrpc"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	"github.com/katocxl/pantherclaw/internal/policy/packs"
)

// The M38 MSSP partner wiring (G0 M38 D1100–D1102, D1100a): PartnerService,
// the decide and open pages, partner sessions on the API and the expiry
// sweep.

// newPartners builds the partner access service. Without entitlements no
// org is a partner (fail closed).
func newPartners(pool *db.Pool, ents *entitlements.Service, publicURL string, log *slog.Logger) *partners.Service {
	var plans partners.Plans
	if ents != nil {
		plans = ents
	}
	return partners.New(pool, plans, publicURL, log)
}

// partnerMayCall reports whether a partner session may call procedure:
// reads (as a support session) and ProposeRollout, nothing else (HR-811).
func partnerMayCall(procedure string) bool {
	return procedure == pantherclawv1connect.PartnerServiceProposeRolloutProcedure || supportMayCall(procedure)
}

// partnerSessions accepts partner sessions on the API.
func partnerSessions(s *partners.Service) rpcauth.Option {
	if s == nil {
		return rpcauth.WithPartnerSessions(nil, nil)
	}
	return rpcauth.WithPartnerSessions(s, partnerMayCall)
}

func m38PartnerPeriodicJobs() []*river.PeriodicJob { return partners.PeriodicJobs() }

// registerM38Partners serves PartnerService and returns the pages' mount;
// nil without a partner service. Accepting a proposal drafts through the
// policy versions and reference packs as the M11 wiring builds them.
func registerM38Partners(rs *connect.Server, d apiDeps) func(mux *http.ServeMux) {
	svc := d.partners
	if svc == nil {
		return nil
	}
	var notify policyapp.Notifier
	if d.m5 != nil && d.m5.notifications != nil {
		notify = d.m5.notifications
	}
	versions := newPolicyVersions(d.pool, notify, d.publicURL, d.cel)
	ps := &packs.Service{Pool: d.pool, Drafts: versions}
	if d.billing != nil {
		ps.Editions = d.billing
	}
	svc.WithDrafts(versions, ps)
	pantherclawv1connect.RegisterPartnerServiceHandler(rs, partnersrpc.New(svc))
	if d.web == nil {
		return nil
	}
	web := d.web
	return func(mux *http.ServeMux) { web.MountPartners(mux, svc) }
}
