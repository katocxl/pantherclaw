// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"maps"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// automationTemplateProcedures are TemplateService's and ProposalService's
// procedures (G0 M11 part 2 D31, D32): reads are automation.read; creating
// from a template and deciding a proposal are automation.manage (human
// only, checked again in the handlers).
var automationTemplateProcedures = map[string]td.Permission{
	pantherclawv1connect.TemplateServiceListTemplatesProcedure:      td.PermAutomationRead,
	pantherclawv1connect.TemplateServiceGetTemplateProcedure:        td.PermAutomationRead,
	pantherclawv1connect.TemplateServiceCreateFromTemplateProcedure: td.PermAutomationManage,
	pantherclawv1connect.ProposalServiceListProposalsProcedure:      td.PermAutomationRead,
	pantherclawv1connect.ProposalServiceDecideProposalProcedure:     td.PermAutomationManage,
}

func init() { maps.Copy(procedurePermissions, automationTemplateProcedures) }
