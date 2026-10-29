// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"maps"
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/externalchecks"
	"github.com/katocxl/pantherclaw/internal/externalchecks/externalchecksrpc"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// externalCheckProcedures are ExternalCheckService's procedures (G0 M16
// D81): changes need policy.external_check.manage (a person, checked again
// by the use cases with the Business edition; activation only on the
// check's page), listing needs policy.read.
var externalCheckProcedures = map[string]td.Permission{
	pantherclawv1connect.ExternalCheckServiceCreateExternalCheckProcedure:   td.PermExternalCheckManage,
	pantherclawv1connect.ExternalCheckServiceActivateExternalCheckProcedure: td.PermExternalCheckManage,
	pantherclawv1connect.ExternalCheckServiceDisableExternalCheckProcedure:  td.PermExternalCheckManage,
	pantherclawv1connect.ExternalCheckServiceListExternalChecksProcedure:    td.PermPolicyRead,
	pantherclawv1connect.ExternalCheckServiceTestExternalCheckProcedure:     td.PermExternalCheckManage,
}

// externalCheckClasses are their plan-gate classes: disabling, like
// disabling a fact provider, stays possible on a lapsed plan.
var externalCheckClasses = map[string]entitlements.Class{
	pantherclawv1connect.ExternalCheckServiceCreateExternalCheckProcedure:   entitlements.ClassChange,
	pantherclawv1connect.ExternalCheckServiceActivateExternalCheckProcedure: entitlements.ClassChange,
	pantherclawv1connect.ExternalCheckServiceDisableExternalCheckProcedure:  entitlements.ClassSafety,
	pantherclawv1connect.ExternalCheckServiceListExternalChecksProcedure:    entitlements.ClassRead,
	pantherclawv1connect.ExternalCheckServiceTestExternalCheckProcedure:     entitlements.ClassChange,
}

func init() {
	maps.Copy(procedurePermissions, externalCheckProcedures)
	maps.Copy(procedureClasses, externalCheckClasses)
}

// newExternalChecks is the process's one external check service: the
// Authority asks it in every role, and the API serves it.
func newExternalChecks(pool *db.Pool, cfg *Config, bill *billing.Service, log *slog.Logger) *externalchecks.Service {
	var editions externalchecks.Editions
	if bill != nil {
		editions = bill
	}
	return externalchecks.New(pool, externalchecks.Config{
		AllowedPrefixes: cfg.ExternalChecks.AllowedPrefixes, PublicURL: cfg.Auth.PublicURL,
	}, editions, log)
}

// wireM16External gives the decision pipeline the org's external policy
// checks (D81).
func wireM16External(svc *authority.Service, ec *externalchecks.Service) {
	if svc == nil || ec == nil {
		return
	}
	svc.WithExternalCheck(ec)
}

// registerM16External serves ExternalCheckService.
func registerM16External(rs *connect.Server, d apiDeps) {
	if d.external == nil {
		return
	}
	pantherclawv1connect.RegisterExternalCheckServiceHandler(rs, externalchecksrpc.New(d.external))
}

// mountM16External adds the activation page (HR-438).
func mountM16External(mux *http.ServeMux, d apiDeps) {
	if d.web == nil || d.external == nil {
		return
	}
	d.web.MountExternalChecks(mux, d.external)
}
