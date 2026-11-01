// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	policyapp "github.com/katocxl/pantherclaw/internal/policy/app"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
	"github.com/katocxl/pantherclaw/internal/signals"
)

// HR-356 on the pages (G0 M22 D77): a page that stands in for a procedure
// passes the plan gate the procedure would, before the step-up and the use
// case. withSession applies it to every state-changing route, and a route
// missing from pagePlans counts as a change, so a new page fails closed.

// PlanGate is the plan gate (entitlements.Gate). Without one, no page is
// refused, as with billing.require_plan off.
type PlanGate interface {
	Check(ctx context.Context, org ids.OrgID, procedure string) error
}

// WithPlanGate adds the plan gate to the pages.
func (h *Handler) WithPlanGate(g PlanGate) *Handler {
	h.planGate = g
	return h
}

// ChangePage names a page that applies a change no procedure stands for: a
// confirmed ceremony. The gate has no class for it, and treats it as a change.
const ChangePage = "page/change"

// SafetyPage names safety work no procedure stands for: approving, a
// reconciliation release, the kill switch, declining a policy change. The
// gate classes it as safety, so a lapsed org keeps it and an org with no
// plan does not (G0 M22 D80).
const SafetyPage = "page/safety"

// PagePlan says how a state-changing page meets the plan gate.
type PagePlan struct {
	// Procedure is what the gate is asked about, by the page's stand-in
	// procedure, or ChangePage or SafetyPage.
	Procedure string
	// Open is why the gate does not apply: the page belongs to the account or
	// to support staff.
	Open string
}

const (
	openAccount = "a person's own session and keys, which every org state keeps"
	openStaff   = "support staff, whose org is not the one the plan belongs to"
)

func on(procedure string) PagePlan { return PagePlan{Procedure: procedure} }

func open(why string) PagePlan { return PagePlan{Open: why} }

// pagePlans names every state-changing page by its route pattern.
var pagePlans = map[string]PagePlan{
	authnapp.LogoutPath:                                    open(openAccount),
	authnapp.AccountPath + "/sessions/{id}/revoke":         on(pantherclawv1connect.AccountServiceRevokeMySessionProcedure),
	authnapp.AccountPath + "/keys/registration-options":    open(openAccount),
	authnapp.AccountPath + "/keys":                         open(openAccount),
	authnapp.AccountPath + "/keys/{id}/rename":             open(openAccount),
	authnapp.AccountPath + "/keys/{id}/remove":             open(openAccount),
	authnapp.AccountPath + "/step-up-options":              open(openAccount),
	authnapp.AccountPath + "/step-up":                      open(openAccount),
	authnapp.ApprovalsPath + "/batch-options":              on(SafetyPage),
	authnapp.ApprovalsPath + "/batch":                      on(SafetyPage),
	authnapp.ApprovalsPath + "/{id}/approve-options":       on(SafetyPage),
	authnapp.ApprovalsPath + "/{id}/approve":               on(SafetyPage),
	authnapp.ApprovalsPath + "/{id}/decline":               on(pantherclawv1connect.ApprovalServiceDeclineApprovalRequestProcedure),
	authnapp.ApprovalsPath + "/{id}/evidence-request":      on(pantherclawv1connect.ApprovalServiceRequestApprovalEvidenceProcedure),
	authnapp.ApprovalsPath + "/{id}/narrower":              on(pantherclawv1connect.ApprovalServiceProposeNarrowerActionProcedure),
	authnapp.ReconciliationsPath + "/{id}/release-options": on(SafetyPage),
	authnapp.ReconciliationsPath + "/{id}/release":         on(SafetyPage),

	rapp.PagePath + "/kill-switch/engage":               on(SafetyPage),
	rapp.PagePath + "/kill-switch/restore":              on(SafetyPage),
	rapp.PagePath + "/kill-switch/restore/{id}/confirm": on(SafetyPage),
	rapp.PagePath + "/kill-switch/restore/{id}/cancel":  on(SafetyPage),

	changes.Path + "/{id}/confirm-options": on(ChangePage),
	changes.Path + "/{id}/confirm":         on(ChangePage),
	changes.Path + "/{id}/decline":         on(pantherclawv1connect.ChangeServiceDeclineChangeRequestProcedure),

	policyapp.ChangesPath + "/{id}/confirm-options": on(pantherclawv1connect.PolicyServicePublishPolicyVersionProcedure),
	policyapp.ChangesPath + "/{id}/confirm":         on(pantherclawv1connect.PolicyServicePublishPolicyVersionProcedure),
	policyapp.ChangesPath + "/{id}/decline":         on(SafetyPage),

	signals.PlaybookPath + "/{id}/confirm-options": on(pantherclawv1connect.SharedSignalsServiceRequestIdentityPlaybookChangeProcedure),
	signals.PlaybookPath + "/{id}/confirm":         on(pantherclawv1connect.SharedSignalsServiceRequestIdentityPlaybookChangeProcedure),
	signals.PlaybookPath + "/{id}/decline":         on(pantherclawv1connect.SharedSignalsServiceDeclineIdentityPlaybookRequestProcedure),

	DestinationsPath + "/{id}/confirm": on(pantherclawv1connect.SIEMServiceSetSIEMDestinationStateProcedure),
	TransmittersPath + "/{id}/confirm": on(pantherclawv1connect.SharedSignalsServiceSetSSFTransmitterStateProcedure),

	ExportDestinationsPath + "/new":             on(pantherclawv1connect.ExportDestinationServiceCreateExportDestinationProcedure),
	ExportDestinationsPath + "/{id}/credential": on(pantherclawv1connect.ExportDestinationServiceReplaceExportDestinationCredentialProcedure),
	ExportDestinationsPath + "/{id}/confirm":    on(pantherclawv1connect.ExportDestinationServiceSetExportDestinationStateProcedure),
	IdentityProvidersPath + "/new":              on(pantherclawv1connect.IdentityProviderServiceCreateIdentityProviderProcedure),

	CredentialRotationsPath + "/{id}/activate": on(pantherclawv1connect.CredentialRotationServiceActivateRotationProcedure),
	CredentialRotationsPath + "/{id}/rollback": on(pantherclawv1connect.CredentialRotationServiceRollBackRotationProcedure),

	ModelDraftingPath + "/enable":    on(pantherclawv1connect.ModelServiceUpdateModelSettingsProcedure),
	ModelDraftingPath + "/key":       on(pantherclawv1connect.ModelServiceUpdateModelSettingsProcedure),
	ModelDraftingPath + "/disable":   on(pantherclawv1connect.ModelServiceDisableModelDraftingProcedure),
	ModelDraftingPath + "/key/clear": on(pantherclawv1connect.ModelServiceClearModelKeyProcedure),

	AutomationSourcesPath + "/{id}/activate":      on(pantherclawv1connect.TriggerServiceActivateEventSourceProcedure),
	AutomationSourcesPath + "/{id}/rotate":        on(pantherclawv1connect.TriggerServiceRotateEventSourceSecretProcedure),
	AutomationDestinationsPath + "/{id}/activate": on(pantherclawv1connect.TriggerServiceActivateAutomationDestinationProcedure),
	AutomationDestinationsPath + "/{id}/rotate":   on(pantherclawv1connect.TriggerServiceRotateAutomationDestinationSecretProcedure),
	AutomationsPath + "/{id}/start":               on(pantherclawv1connect.TriggerServiceStartExecutionProcedure),
	AutomationsPath + "/executions/{id}/retry":    on(pantherclawv1connect.TriggerServiceRetryExecutionProcedure),

	PromotionsPath + "/{id}/promote":         on(pantherclawv1connect.PromotionServicePromoteAgentProcedure),
	ProtectedChangesPath + "/{id}/emergency": on(pantherclawv1connect.ProtectedChangeServiceApplyEmergencyProtectedChangeProcedure),
	CompromisePath:                           on(pantherclawv1connect.PublisherServiceMarkCompromisedProcedure),

	"/break-glass/activate":                      on(pantherclawv1connect.BreakGlassServiceActivateBreakGlassProcedure),
	"/connections/{id}/a2a-pin/{pin}/confirm":    on(pantherclawv1connect.ConnectionServiceUpdateConnectionProcedure),
	"/connections/{id}/postgres/confirm":         on(pantherclawv1connect.ConnectionServiceUpdateConnectionProcedure),
	"/enforcement-points/{id}/activate":          on(pantherclawv1connect.EnforcementPointServiceActivateEnforcementPointProcedure),
	"/policies/external-checks/{id}/activate":    on(pantherclawv1connect.ExternalCheckServiceActivateExternalCheckProcedure),
	"/notifications/channels/{id}/confirm":       on(pantherclawv1connect.NotificationServiceUpdateChannelProcedure),
	"/notifications/channels/{id}/confirm-teams": on(pantherclawv1connect.NotificationServiceUpdateChannelProcedure),

	"/support-access/request":                  open(openStaff),
	"/support-access/requests/{org}/{id}/open": open(openStaff),
	"/support-access/{id}/approve":             on(pantherclawv1connect.SupportAccessServiceApproveSupportRequestProcedure),
	"/support-access/{id}/deny":                on(pantherclawv1connect.SupportAccessServiceDenySupportRequestProcedure),
}

// PagePlanOf returns how a state-changing route pattern meets the plan gate,
// and whether it names one.
func PagePlanOf(path string) (PagePlan, bool) {
	p, ok := pagePlans[path]
	return p, ok
}

// planAllows runs the plan gate for a state-changing route and answers a
// refusal. A route with no entry is a change.
func (h *Handler) planAllows(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession, path string) bool {
	plan := pagePlans[path]
	if h.planGate == nil || plan.Open != "" {
		return true
	}
	if plan.Procedure == "" {
		plan.Procedure = ChangePage
	}
	err := h.planGate.Check(r.Context(), s.Org, plan.Procedure)
	switch {
	case err == nil:
		return true
	case pcerr.ReasonOf(err) == "PLAN_REQUIRED":
		h.jsonError(w, http.StatusConflict, "plan_required")
	default:
		h.log.ErrorContext(r.Context(), "web.plan_gate", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
	}
	return false
}
