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
	defspg "github.com/katocxl/pantherclaw/internal/definitions/adapters/pgstore"
	defsdomain "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
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
	automationStarter    func(core *automationsCore, pool *db.Pool, bill *billing.Service, log *slog.Logger) (autoports.Starter, error)
	automationExecutions func(core *automationsCore, pool *db.Pool, bill *billing.Service, log *slog.Logger) (triggers.ExecutionLookup, error)
	automationPauser     func(core *automationsCore) autoports.Pauser
)

// newAutomationTriggers builds the trigger service as pc_app. The engine's
// and core's ports come from the process's one core (D105); without it
// (nil) they read as "not available". An engine that cannot be built is an
// error (D120).
func newAutomationTriggers(pool *db.Pool, bill *billing.Service, log *slog.Logger, core *automationsCore) (*triggers.Service, error) {
	d := triggers.Deps{
		Pool: pool, Raiser: m10Raiser{pool: pool}, Failures: &failures.Sink{}, Operations: automationOperations{store: &defspg.Store{Pool: pool}},
		Clock: clock.System{}, Log: log,
	}
	if bill != nil {
		d.Editions = bill
	}
	if core != nil && automationStarter != nil {
		starter, err := automationStarter(core, pool, bill, log)
		if err != nil {
			return nil, err
		}
		d.Starter = starter
	}
	if core != nil && automationExecutions != nil {
		lookup, err := automationExecutions(core, pool, bill, log)
		if err != nil {
			return nil, err
		}
		d.Executions = lookup
	}
	if core != nil && automationPauser != nil {
		d.Pauser = automationPauser(core)
	}
	s := triggers.New(d)
	probeM11("automations.triggers", s)
	return s, nil
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

// automationTriggerServices builds the trigger and endpoints services the
// API and the workers serve, on the process's shared core (D112).
func automationTriggerServices(pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, publicURL string,
	clientIP httpx.ClientIPFunc, core *automationsCore, log *slog.Logger,
) (*triggers.Service, *endpoints.Service, error) {
	trig, err := newAutomationTriggers(pool, bill, log, core)
	if err != nil {
		return nil, nil, err
	}
	ep, err := newAutomationEndpoints(pool, kp, trig, bill, publicURL, clientIP, log)
	if err != nil {
		return nil, nil, err
	}
	return trig, ep, nil
}

// automationTriggerActivator is the TriggerActivator core calls when it
// enables, pauses or resumes an automation (D11).
func automationTriggerActivator(pool *db.Pool, bill *billing.Service, log *slog.Logger, core *automationsCore,
) (autoports.TriggerActivator, error) {
	trig, err := newAutomationTriggers(pool, bill, log, core)
	if err != nil {
		return nil, err
	}
	return trig.Activator(), nil
}

// automationDeliverer is the Deliverer the engine's deliver and notify
// steps use (D22), over trig: a trigger service that, like every one, the
// caller built on the process's shared core (D112).
func automationDeliverer(pool *db.Pool, kp keys.KeyProvider, trig *triggers.Service, bill *billing.Service, publicURL string,
	log *slog.Logger,
) (autoports.Deliverer, error) {
	ep, err := newAutomationEndpoints(pool, kp, trig, bill, publicURL, nil, log)
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
// endpoint and pages, with the process's shared core (its Starter and
// Pauser) passed explicitly (D109 E3).
func registerAutomationTriggers(rs *connect.Server, d apiDeps, autos *automationsCore) (m11Triggers, error) {
	trig, ep, err := automationTriggerServices(d.pool, d.kp, d.billing, d.publicURL, d.clientIP, autos, d.log)
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
	bill *billing.Service, publicURL string, core *automationsCore, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	trig, ep, err := automationTriggerServices(pool, kp, bill, publicURL, nil, core, log)
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

func (p automationPages) RetryExecution(ctx context.Context, execution ids.UUID, idem string, su *stepup.StepUp) (triggers.Outcome, error) {
	return p.trig.RetryExecution(ctx, execution, idem, su)
}

// automationOperations answers the trigger service's operation lookup in
// the trigger's own transaction (D97 N3): the org's ACTIVE definition of
// op from the highest active version that defines it, as the definitions
// store's Active does.
type automationOperations struct{ store *defspg.Store }

func (o automationOperations) Active(ctx context.Context, tx db.TenantTx, org ids.OrgID, op string) (*defsdomain.Definition, error) {
	rows, err := dbq.New(tx).ListActiveVersionsWith(ctx, org, op)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	best := rows[0]
	for _, r := range rows[1:] {
		a, err1 := defsdomain.ParseVersion(r.Version)
		b, err2 := defsdomain.ParseVersion(best.Version)
		if err1 == nil && err2 == nil && a.Compare(b) > 0 {
			best = r
		}
	}
	p, err := o.store.VersionInTx(ctx, tx, org, best.ID)
	if err != nil {
		return nil, err
	}
	d, _ := p.Definition(op)
	return d, nil
}
