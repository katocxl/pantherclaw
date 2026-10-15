// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/billing"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	"github.com/katocxl/pantherclaw/internal/reflex/failures"
	"github.com/katocxl/pantherclaw/internal/reflex/feed"
	reflexports "github.com/katocxl/pantherclaw/internal/reflex/ports"
	"github.com/katocxl/pantherclaw/internal/siem"
	"github.com/katocxl/pantherclaw/internal/siem/siemrpc"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	"github.com/katocxl/pantherclaw/internal/signals"
	"github.com/katocxl/pantherclaw/internal/signals/signalsrpc"
)

// The M10 edges (G0 M10 D35–D39): SIEM export and the Shared Signals
// receiver, both Business. The API serves SIEMService and
// SharedSignalsService, the activation pages and the RFC 8935 push
// endpoint; workers run the exporter and the received-events janitor.

// edgesRaiser is the Raiser edges signals go through (core, D14).
func edgesRaiser() reflexports.Raiser { return &alerts.Raiser{} }

// edgesCaseOpener and edgesContainer are the cases and response ports the
// receiver and the identity playbook use (D49): Ops wires the real
// providers. Nil until then: accepted events are recorded with "case not
// opened: cases unavailable" and the playbook refuses to be enabled.
var (
	edgesCaseOpener func(pool *db.Pool) reflexports.CaseOpener
	edgesContainer  func(pool *db.Pool) reflexports.Container
)

// edgesFailures is the owned failure sink (core, D18).
func edgesFailures() reflexports.FailureSink { return &failures.Sink{} }

// newSIEM builds the export service as pc_app: destination secrets under
// the org's DEKs, the evidence feed, the licence and Operations' health
// reporting.
func newSIEM(pool *db.Pool, kp keys.KeyProvider, bill *billing.Service, notify siem.Notifier, publicURL string, log *slog.Logger) (
	*siem.Service, error,
) {
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	svc, err := siem.New(pool, env, feed.Reader{}, siem.Config{PublicURL: publicURL, ProductVersion: version.Get().Version},
		clock.System{}, log)
	if err != nil {
		return nil, err
	}
	health := siem.ReflexHealth{Failures: edgesFailures(), Raiser: edgesRaiser()}
	if notify != nil {
		health.Notify = notify
	}
	svc.WithHealthSink(health).WithFailures(edgesFailures())
	if bill != nil {
		svc.WithEditions(bill)
	}
	return svc, nil
}

// newSignals builds the Shared Signals service as pc_app.
func newSignals(pool *db.Pool, bill *billing.Service, notify siem.Notifier, publicURL string, log *slog.Logger) (*signals.Service, error) {
	svc, err := signals.New(pool, signals.Config{PublicURL: publicURL}, clock.System{}, log)
	if err != nil {
		return nil, err
	}
	svc.WithFailures(edgesFailures()).WithRaiser(edgesRaiser())
	if notify != nil {
		svc.WithNotifier(notify)
	}
	if edgesCaseOpener != nil {
		svc.WithCases(edgesCaseOpener(pool))
	}
	if edgesContainer != nil {
		svc.WithContainer(edgesContainer(pool))
	}
	if bill != nil {
		svc.WithEditions(bill)
	}
	return svc, nil
}

// edgesNotifier is the M5 notifier, when there is one.
func edgesNotifier(m5 *m5Services) siem.Notifier {
	if m5 != nil && m5.notifications != nil {
		return m5.notifications
	}
	return nil
}

// m10Edges is what the API mounts outside Connect.
type m10Edges struct {
	receiver *signals.Receiver
}

// mount adds the Shared Signals push endpoint (public: the SET itself is
// the credential, HR-261).
func (e m10Edges) mount(mux *http.ServeMux) {
	if e.receiver != nil {
		e.receiver.Mount(mux)
	}
}

// registerM10Edges serves SIEMService and SharedSignalsService and adds
// the activation pages when the browser pages are mounted.
func registerM10Edges(rs *connect.Server, d apiDeps) (m10Edges, error) {
	s, err := newSIEM(d.pool, d.kp, d.billing, edgesNotifier(d.m5), d.publicURL, d.log)
	if err != nil {
		return m10Edges{}, err
	}
	sig, err := newSignals(d.pool, d.billing, edgesNotifier(d.m5), d.publicURL, d.log)
	if err != nil {
		return m10Edges{}, err
	}
	pantherclawv1connect.RegisterSIEMServiceHandler(rs, siemrpc.New(s))
	pantherclawv1connect.RegisterSharedSignalsServiceHandler(rs, signalsrpc.New(sig))
	if d.web != nil {
		d.web.WithIntegrations(integrations{siem: s, signals: sig})
		if d.m5 != nil && d.m5.webauthn != nil {
			d.web.WithPlaybook(sig, d.m5.webauthn)
		}
	}
	return m10Edges{receiver: sig.Receiver(d.clientIP)}, nil
}

// registerM10EdgesJobs adds the exporter and the janitor and returns their
// schedules.
func registerM10EdgesJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, pool *db.Pool, kp keys.KeyProvider,
	bill *billing.Service, m5 *m5Services, publicURL string, log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	s, err := newSIEM(pool, kp, bill, edgesNotifier(m5), publicURL, log)
	if err != nil {
		return nil, err
	}
	exp, err := siem.RegisterExport(reg, s)
	if err != nil {
		return nil, err
	}
	sig, err := newSignals(pool, bill, edgesNotifier(m5), publicURL, log)
	if err != nil {
		return nil, err
	}
	jan, err := signals.RegisterJanitor(reg, sig)
	if err != nil {
		return nil, err
	}
	return append(append(periodic, exp...), jan...), nil
}

// integrations adapts the edges services to the activation pages.
type integrations struct {
	siem    *siem.Service
	signals *signals.Service
}

func (i integrations) Destination(ctx context.Context, id ids.UUID) (siem.Destination, error) {
	return i.siem.Get(ctx, id)
}

func (i integrations) ActivateDestination(ctx context.Context, id ids.UUID, su stepup.StepUp) (siem.Destination, error) {
	return i.siem.Activate(ctx, id, su)
}

func (i integrations) Transmitter(ctx context.Context, id ids.UUID) (signals.Transmitter, error) {
	return i.signals.Get(ctx, id)
}

func (i integrations) ActivateTransmitter(ctx context.Context, id ids.UUID, su stepup.StepUp) (signals.Transmitter, error) {
	return i.signals.Activate(ctx, id, su)
}
