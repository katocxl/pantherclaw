// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"time"

	"connectrpc.com/connect/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/entitlements"
	"github.com/katocxl/pantherclaw/internal/extension"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// Per-org entitlements (G0 UI D9, D12, D37, D43): the plan behind every
// gate and limit, the PLAN_REQUIRED gate, EntitlementService, and the plan
// writer and billing links the extension gets.

// newEntitlements builds the per-org plan source and makes the licence
// service per org, so every existing gate and limit reads the org's plan.
func newEntitlements(cfg *Config, pool *db.Pool, bill *billing.Service, log *slog.Logger) (*entitlements.Service, error) {
	svc, err := entitlements.New(pool, entitlements.LicenceFunc(bill.Licence), cfg.billingMode(), clock.System{}, log)
	if err != nil {
		return nil, err
	}
	bill.UseOrgEntitlements(svc)
	return svc, nil
}

// planGate is the rpcauth plan gate (HR-356): org calls only.
func planGate(svc *entitlements.Service, require bool) func(ctx context.Context, c tapp.Caller, procedure string) error {
	g := entitlements.NewGate(svc, require, procedureClass)
	return func(ctx context.Context, c tapp.Caller, procedure string) error {
		return g.Check(ctx, c.Org, procedure)
	}
}

// entitlementService serves EntitlementService.
type entitlementService struct {
	pantherclawv1connect.UnimplementedEntitlementServiceHandler
	svc *entitlements.Service
}

// registerUIEntitlements serves EntitlementService.
func registerUIEntitlements(rs *connect.Server, d apiDeps) {
	if d.ui == nil || d.ui.ents == nil {
		pantherclawv1connect.RegisterEntitlementServiceHandler(rs, entitlementService{})
		return
	}
	pantherclawv1connect.RegisterEntitlementServiceHandler(rs, entitlementService{svc: d.ui.ents})
}

// GetEntitlements implements EntitlementServiceHandler.
func (s entitlementService) GetEntitlements(ctx context.Context, _ *pantherclawv1.GetEntitlementsRequest) (*pantherclawv1.GetEntitlementsResponse, error) {
	if s.svc == nil {
		return nil, connect.NewError(connect.CodeUnimplemented, "entitlements are not served")
	}
	v, err := s.svc.Get(ctx)
	if err != nil {
		return nil, err
	}
	return &pantherclawv1.GetEntitlementsResponse{Entitlements: entitlementsProto(v)}, nil
}

var planStatusProto = map[entitlements.Status]pantherclawv1.PlanStatus{
	entitlements.StatusNone: pantherclawv1.PlanStatus_PLAN_STATUS_NONE, entitlements.StatusTrialing: pantherclawv1.PlanStatus_PLAN_STATUS_TRIALING,
	entitlements.StatusActive: pantherclawv1.PlanStatus_PLAN_STATUS_ACTIVE, entitlements.StatusPastDue: pantherclawv1.PlanStatus_PLAN_STATUS_PAST_DUE,
	entitlements.StatusPaused: pantherclawv1.PlanStatus_PLAN_STATUS_PAUSED, entitlements.StatusCanceled: pantherclawv1.PlanStatus_PLAN_STATUS_CANCELED,
	entitlements.StatusLapsed: pantherclawv1.PlanStatus_PLAN_STATUS_LAPSED, entitlements.StatusComp: pantherclawv1.PlanStatus_PLAN_STATUS_COMP,
	entitlements.StatusDev: pantherclawv1.PlanStatus_PLAN_STATUS_DEV,
}

var planSourceProto = map[entitlements.Source]pantherclawv1.PlanSource{
	entitlements.SourceLicence: pantherclawv1.PlanSource_PLAN_SOURCE_LICENCE, entitlements.SourceBilling: pantherclawv1.PlanSource_PLAN_SOURCE_BILLING,
	entitlements.SourceComp: pantherclawv1.PlanSource_PLAN_SOURCE_COMP, entitlements.SourceDev: pantherclawv1.PlanSource_PLAN_SOURCE_DEV,
}

func entitlementsProto(v entitlements.View) *pantherclawv1.Entitlements {
	p := v.Plan
	out := &pantherclawv1.Entitlements{
		PlanId: p.PlanID, Edition: p.Edition, Status: planStatusProto[p.Status], Source: planSourceProto[p.Source],
		Features: p.Features,
		Limits: &pantherclawv1.PlanLimits{
			MaxAgents: int32(p.Limits.MaxAgents), MaxEnvironments: int32(p.Limits.MaxEnvironments), //nolint:gosec // G115: ≤ 10^9
			RetentionDays: int32(p.Limits.RetentionDays), InstanceAllowance: int32(p.Limits.InstanceAllowance), //nolint:gosec // G115: ≤ 10^9
			MaxMembers: int32(p.Limits.MaxMembers), //nolint:gosec // G115: ≤ 10^9
		},
		Usage: &pantherclawv1.PlanUsage{
			Agents: int32(v.Usage.Agents), Environments: int32(v.Usage.Environments), Members: int32(v.Usage.Members), //nolint:gosec // G115: counts
		},
	}
	if p.PeriodEnd != nil {
		out.PeriodEnd = timestamppb.New(*p.PeriodEnd)
	}
	if p.CompUntil != nil {
		out.CompUntil = timestamppb.New(*p.CompUntil)
	}
	return out
}

// planWriter is extension.PlanWriter over the entitlements service.
type planWriter struct{ svc *entitlements.Service }

// ApplyPlan implements extension.PlanWriter (HR-354, HR-355, HR-361).
func (w planWriter) ApplyPlan(ctx context.Context, orgID string, s extension.PlanSnapshot) error {
	org, err := ids.Parse[ids.Org](orgID)
	if err != nil {
		return entitlements.ErrUnknownOrg
	}
	return w.svc.ApplyPlan(ctx, org, entitlements.Snapshot{
		PlanID: s.PlanID, Edition: s.Edition, Status: entitlements.Status(s.Status), Features: s.Features,
		Limits: entitlements.Limits{
			MaxAgents: s.Limits.MaxAgents, MaxEnvironments: s.Limits.MaxEnvironments, RetentionDays: s.Limits.RetentionDays,
			InstanceAllowance: s.Limits.InstanceAllowance, MaxMembers: s.Limits.MaxMembers,
		},
		PeriodEnd: s.PeriodEnd, EventID: s.EventID, EventAt: s.EventAt,
	})
}

// billingLinks is the extension's view of the billing links (D37, D45,
// D46, D52). extension.BillingLinks is added by the core-web stream; the
// method set below is its contract.
type billingLinks struct{ l *entitlements.Links }

// RecordCheckout records a checkout the server created for an org.
func (b billingLinks) RecordCheckout(ctx context.Context, orgID, provider, checkoutRef string, expiresAt time.Time) (string, error) {
	return b.l.RecordCheckout(ctx, orgID, provider, checkoutRef, expiresAt)
}

// BindSubscription binds a subscription through its recorded checkout.
func (b billingLinks) BindSubscription(ctx context.Context, provider, checkoutRef, subscriptionRef, customerRef string) (string, error) {
	return b.l.BindSubscription(ctx, provider, checkoutRef, subscriptionRef, customerRef)
}

// SubscriptionOrg returns a subscription's org and whether it is current.
func (b billingLinks) SubscriptionOrg(ctx context.Context, provider, subscriptionRef string) (string, bool, error) {
	return b.l.SubscriptionOrg(ctx, provider, subscriptionRef)
}

// EndSubscription ends a subscription.
func (b billingLinks) EndSubscription(ctx context.Context, provider, subscriptionRef string) error {
	return b.l.EndSubscription(ctx, provider, subscriptionRef)
}

// CurrentSubscription returns an org's current subscription.
func (b billingLinks) CurrentSubscription(ctx context.Context, orgID, provider string) (string, bool, error) {
	return b.l.CurrentSubscription(ctx, orgID, provider)
}
