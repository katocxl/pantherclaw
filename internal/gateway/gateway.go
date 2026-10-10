// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/hook"
	"github.com/katocxl/pantherclaw/internal/gateway/httpproxy"
	"github.com/katocxl/pantherclaw/internal/gateway/mcp"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// PAP/1 request headers, for clients of the gateway (dispatch).
const (
	HeaderProof    = dispatch.HeaderProof
	HeaderNonce    = dispatch.HeaderNonce
	HeaderError    = dispatch.HeaderError
	HeaderRunID    = dispatch.HeaderRunID
	HeaderActionID = dispatch.HeaderActionID
)

// Containment is the gateway's view of its org's containment (HR-010):
// control.Containment, fed by the WatchContainment stream.
type Containment interface {
	dispatch.Containment
	// Ready closes when the first snapshot arrived.
	Ready() <-chan struct{}
}

// Gateway is the enforcement point: the HTTP face over the one dispatch
// path, with the background work that keeps its identity, containment,
// configuration and broker key current.
type Gateway struct {
	run         []func(ctx context.Context) error
	containment Containment
	config      Configuration
	broker      *Broker
	engine      *dispatch.Engine
	http        *httpproxy.Handler
	mcp         *mcp.Handler
	hook        *hook.Handler
	log         *slog.Logger
	// reportDrift, driftEvery and driftPoll drive the drift checks
	// (drift.go).
	reportDrift           DriftReporter
	driftEvery, driftPoll time.Duration
	// verifications and verifyEvery drive the verification reads
	// (verify.go, G0 M7).
	verifications Verifications
	verifyEvery   time.Duration
}

// Handler returns the gateway's agent-facing HTTP handler: `/mcp/{connection}`
// (mcp), `/hook/{connection}` (hook) and `/{connection}/…` (httpproxy).
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := mcp.Path(r.URL.EscapedPath()); ok {
			g.mcp.ServeHTTP(w, r)
			return
		}
		if _, ok := hook.Path(r.URL.EscapedPath()); ok {
			g.hook.ServeHTTP(w, r)
			return
		}
		g.http.ServeHTTP(w, r)
	})
}

// Deps are what the gateway takes from the control plane. New builds them
// over mutual TLS from the gateway's identity; tests build them directly.
type Deps struct {
	// Org and GatewayID come from the gateway's certificate (HR-181).
	Org       string
	GatewayID string
	Authority pantherclawv1connect.AuthorityServiceClient
	// JWKSURL and JWKSClient fetch the permit keys (from the gateway
	// listener, over mTLS).
	JWKSURL     string
	JWKSClient  *http.Client
	Containment Containment
	// Broker is the registered broker key; nil without one.
	Broker *Broker
	// Configuration is what the gateway serves (control.Store).
	Configuration Configuration
	// ReportCircuit tells the server a connection's circuit opened
	// (HR-078); nil reports nothing.
	ReportCircuit dispatch.Reporter
	// ReportDrift tells the server an upstream MCP tool drifted (HR-081);
	// nil reports nothing.
	ReportDrift DriftReporter
	// Verifications claims and reports verification tasks (G0 M7); nil
	// makes no verification reads.
	Verifications Verifications
	// Run is background work (certificate renewal, the containment stream,
	// configuration sync); nil for none.
	Run []func(ctx context.Context) error
}

// Configuration is the gateway's configuration (G0 M6 design decision 19):
// control.Store, loaded before serving and kept current.
type Configuration interface {
	// Current returns the configuration, nil before the first load.
	Current() *control.Config
	// Ready closes when the first configuration loaded.
	Ready() <-chan struct{}
}

// New builds a Gateway for an enrolled identity.
func New(ctx context.Context, cfg *Config, id *control.Identity, log *slog.Logger) (*Gateway, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	ctl := control.NewClient(id, cfg.Control.IdentityDir, cfg.Control.GatewayURL, cfg.Control.Timeout.D(), log)
	k := control.NewContainment(ctl, log)
	store := control.NewStore(ctl, log)
	k.OnConfig(store.Changed)
	d := Deps{
		Org: id.Org.String(), GatewayID: id.Gateway.String(), Authority: ctl.Authority,
		JWKSURL: ctl.BaseURL() + "/.well-known/pantherclaw/jwks.json", JWKSClient: ctl.HTTPClient(),
		Containment: k, Configuration: store, Run: []func(context.Context) error{ctl.Run, k.Run, store.Run},
		ReportCircuit: func(ctx context.Context, conn string, unknown, total int32) error {
			_, err := ctl.Gateway.ReportCircuit(ctx, &pb.ReportCircuitRequest{ConnectionId: conn, UnknownCount: unknown, TotalCount: total})
			return err
		},
		ReportDrift: func(ctx context.Context, conn string, d dispatch.Drift) error {
			_, err := ctl.Gateway.ReportDrift(ctx, &pb.ReportDriftRequest{
				ConnectionId: conn, Tool: d.Tool, ExpectedDigest: d.Expected, ObservedDigest: d.Observed,
			})
			return err
		},
		Verifications: controlVerifications{ctl},
	}
	if cfg.Broker.KeyFile != "" {
		key, err := broker.Load(ctx, cfg.Broker.KeyFile, cfg.Broker.KEKFiles)
		if err != nil {
			return nil, err
		}
		d.Broker = NewBroker(key, func(ctx context.Context, public []byte) (string, error) {
			res, err := ctl.Gateway.RegisterBrokerKey(ctx, &pb.RegisterBrokerKeyRequest{PublicKey: public})
			return res.GetBrokerKey().GetId(), err
		}, log)
		d.Run = append(d.Run, d.Broker.Run)
	}
	return newGateway(cfg, d, log)
}

func newGateway(cfg *Config, d Deps, log *slog.Logger) (*Gateway, error) {
	if d.Org == "" || d.GatewayID == "" || d.Authority == nil || d.JWKSClient == nil || d.Containment == nil || d.Configuration == nil {
		return nil, errors.New("gateway: incomplete control-plane dependencies")
	}
	prefixes, err := cfg.allowedPrefixes()
	if err != nil {
		return nil, err
	}
	o := dispatch.Options{
		Org: d.Org, GatewayID: d.GatewayID, Authority: d.Authority, JWKSURL: d.JWKSURL, JWKSClient: d.JWKSClient,
		Containment: d.Containment, AllowedPrefixes: prefixes, ReportCircuit: d.ReportCircuit, Log: log,
		Approvers: proof.NewPinned(cfg.Approvals.ApproverKeysFile, d.Org),
	}
	if d.Broker != nil {
		o.Broker = d.Broker
	}
	var g *Gateway
	// A call's own check reports drift at once, as the loop's does. Calls
	// start only once g is set.
	o.OnDrift = func(ctx context.Context, connection string, dr dispatch.Drift) { g.drifted(ctx, connection, dr) }
	engine, err := dispatch.New(o)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = pclog.Discard()
	}
	g = &Gateway{
		run: d.Run, containment: d.Containment, config: d.Configuration, broker: d.Broker, engine: engine,
		http: httpproxy.New(engine, d.Configuration, cfg.PublicURL, log),
		mcp:  mcp.New(engine, d.Configuration, cfg.PublicURL, log),
		hook: hook.New(engine, d.Configuration, cfg.PublicURL, log),
		log:  log, reportDrift: d.ReportDrift, driftEvery: DriftEvery, driftPoll: driftPoll,
		verifications: d.Verifications, verifyEvery: VerifyEvery,
	}
	if e := cfg.Control.VerifyEvery.D(); e > 0 {
		g.verifyEvery = e
	}
	return g, nil
}

// Run does the gateway's background work until ctx ends.
func (g *Gateway) Run(ctx context.Context) error {
	eg, ctx := errgroup.WithContext(ctx)
	for _, f := range g.run {
		eg.Go(func() error { return f(ctx) })
	}
	eg.Go(func() error { return g.watchDrift(ctx) })
	eg.Go(func() error { return g.watchVerifications(ctx) })
	eg.Go(func() error { <-ctx.Done(); return nil })
	return eg.Wait()
}

// ConfigVersion is the version of the configuration the gateway serves, 0
// before the first load. A change (a new connection, a sealed credential)
// is served once this reaches the version the server returned for it.
func (g *Gateway) ConfigVersion() int64 {
	if c := g.config.Current(); c != nil {
		return c.Version
	}
	return 0
}

// WaitReady returns once the first containment snapshot and the first
// configuration arrived: the gateway serves nothing before (HR-010,
// decision 19).
func (g *Gateway) WaitReady(ctx context.Context, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	defer t.Stop()
	waits := []struct {
		ready <-chan struct{}
		what  string
	}{{g.containment.Ready(), "containment snapshot"}, {g.config.Ready(), "configuration"}}
	if g.broker != nil {
		waits = append(waits, struct {
			ready <-chan struct{}
			what  string
		}{g.broker.Ready(), "broker key registration"})
	}
	for _, w := range waits {
		select {
		case <-w.ready:
		case <-ctx.Done():
			return ctx.Err()
		case <-t.C:
			return fmt.Errorf("gateway: no %s from the server within %s", w.what, timeout)
		}
	}
	return nil
}
