// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	autoports "github.com/katocxl/pantherclaw/internal/automations/ports"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/adapters/triggersrpc"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
)

// Automation triggers (G0 M11 part 2 D16–D23, D53): the API serves
// TriggerService, the automation endpoint pages and the signed inbound
// endpoint (outside Connect); workers run the feed consumer, schedules,
// conditions, deliveries and the janitor.
//
// Cross-stream ports, set by the streams that own them (a port left nil
// reads as "not available"): the engine's Starter and execution lookup,
// core's Pauser. Core and engine take this stream's TriggerActivator and
// Deliverer from automationTriggerActivator and automationDeliverer.
var (
	automationStarter    func(pool *db.Pool, bill *billing.Service, log *slog.Logger) autoports.Starter
	automationExecutions func(pool *db.Pool) triggers.ExecutionLookup
	automationPauser     func(pool *db.Pool) autoports.Pauser
)

// newAutomationTriggers builds the trigger service as pc_app.
func newAutomationTriggers(pool *db.Pool, bill *billing.Service, log *slog.Logger) *triggers.Service {
	d := triggers.Deps{Pool: pool, Raiser: m10Raiser{pool: pool}, Failures: &failures.Sink{}, Clock: clock.System{}, Log: log}
	if bill != nil {
		d.Editions = bill
	}
	if automationStarter != nil {
		d.Starter = automationStarter(pool, bill, log)
	}
	if automationExecutions != nil {
		d.Executions = automationExecutions(pool)
	}
	if automationPauser != nil {
		d.Pauser = automationPauser(pool)
	}
	return triggers.New(d)
}

// newAutomationEndpoints builds the endpoints service: secrets under the
// org's DEKs.
func newAutomationEndpoints(pool *db.Pool, kp keys.KeyProvider, trig *triggers.Service, bill *billing.Service,
	publicURL string, clientIP httpx.ClientIPFunc, log *slog.Logger,
) (*endpoints.Service, error) {
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	var ed triggers.Editions
	if bill != nil {
		ed = bill
	}
	ep, err := endpoints.New(pool, env, trig, ed, endpoints.Config{PublicURL: publicURL, ClientIP: clientIP}, clock.System{}, log)
	if err != nil {
		return nil, err
	}
	return ep.WithFailures(&failures.Sink{}), nil
}

// automationTriggerActivator is the TriggerActivator core calls when it
// enables, pauses or resumes an automation (D11).
func automationTriggerActivator(pool *db.Pool, bill *billing.Service, log *slog.Logger) autoports.TriggerActivator {
	return newAutomationTriggers(pool, bill, log).Activator()
}

// automationDeliverer is the Deliverer the engine's deliver and notify
// steps use (D22).
func automationDeliverer(pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, publicURL string, log *slog.Logger) (autoports.Deliverer, error) {
	ep, err := newAutomationEndpoints(pool, kp, newAutomationTriggers(pool, bill, log), bill, publicURL, nil, log)
	if err != nil {
		return nil, err
	}
	return ep.Deliverer(), nil
}

// m11Triggers is what the API mounts outside Connect.
type m11Triggers struct {
	receiver *endpoints.Receiver
	web      func(mux *http.ServeMux)
}

// mount adds the inbound endpoint (public: the signature is the
// credential, HR-275) and the endpoint pages.
func (m m11Triggers) mount(mux *http.ServeMux) {
	if m.receiver != nil {
		m.receiver.Mount(mux)
	}
	if m.web != nil {
		m.web(mux)
	}
}

// registerAutomationTriggers serves TriggerService and prepares the
// endpoint and pages.
func registerAutomationTriggers(rs *connect.Server, d apiDeps) (m11Triggers, error) {
	trig := newAutomationTriggers(d.pool, d.billing, d.log)
	ep, err := newAutomationEndpoints(d.pool, d.kp, trig, d.billing, d.publicURL, d.clientIP, d.log)
	if err != nil {
		return m11Triggers{}, err
	}
	pantherclawv1connect.RegisterTriggerServiceHandler(rs, triggersrpc.New(trig, ep, d.publicURL))
	out := m11Triggers{receiver: ep.Receiver()}
	if d.web != nil {
		web := d.web
		pages := automationPages{trig: trig, ep: ep}
		out.web = func(mux *http.ServeMux) { web.MountAutomationEndpoints(mux, pages) }
	}
	return out, nil
}

// registerAutomationTriggersJobs adds the trigger workers and returns
// their schedules.
func registerAutomationTriggersJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider,
	bill *billing.Service, publicURL string, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	trig := newAutomationTriggers(pool, bill, log)
	ep, err := newAutomationEndpoints(pool, kp, trig, bill, publicURL, nil, log)
	if err != nil {
		return nil, err
	}
	p, err := triggers.Register(reg, trig, ep)
	if err != nil {
		return nil, err
	}
	return append(periodic, p...), nil
}

// automationPages adapts the trigger services to the endpoint pages.
type automationPages struct {
	trig *triggers.Service
	ep   *endpoints.Service
}

func (p automationPages) EventSource(ctx context.Context, id ids.UUID) (endpoints.Source, error) {
	return p.ep.GetEventSource(ctx, id)
}

func (p automationPages) ActivateEventSource(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Source, error) {
	return p.ep.ActivateEventSource(ctx, id, su)
}

func (p automationPages) RotateEventSourceSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	return p.ep.RotateEventSourceSecret(ctx, id, su)
}

func (p automationPages) Destination(ctx context.Context, id ids.UUID) (endpoints.Destination, error) {
	return p.ep.GetDestination(ctx, id)
}

func (p automationPages) ActivateDestination(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Destination, error) {
	return p.ep.ActivateDestination(ctx, id, su)
}

func (p automationPages) RotateDestinationSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error) {
	return p.ep.RotateDestinationSecret(ctx, id, su)
}

func (p automationPages) Form(ctx context.Context, automation ids.UUID) (triggers.ManualForm, error) {
	return p.trig.Form(ctx, automation)
}

func (p automationPages) StartExecution(ctx context.Context, in triggers.ManualStart, su *stepup.StepUp) (triggers.Outcome, error) {
	return p.trig.StartExecution(ctx, in, su)
}
