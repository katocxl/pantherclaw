// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/approvals/proof"
	"github.com/katocxl/pantherclaw/internal/gateway/a2aface"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/browsercompare"
	"github.com/katocxl/pantherclaw/internal/gateway/connectors"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/hook"
	"github.com/katocxl/pantherclaw/internal/gateway/httpproxy"
	"github.com/katocxl/pantherclaw/internal/gateway/mcp"
	"github.com/katocxl/pantherclaw/internal/gateway/mcpauth"
	"github.com/katocxl/pantherclaw/internal/gateway/modelface"
	runtimeface "github.com/katocxl/pantherclaw/internal/gateway/runtime"
	"github.com/katocxl/pantherclaw/internal/gateway/sdk"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/docker"
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
	// mcpOAuth is the MCP face's OAuth route (G0 M26 D402).
	mcpOAuth *mcpauth.Handler
	hook     *hook.Handler
	sdk      *sdk.Handler
	a2a      *a2aface.Handler
	model    *modelface.Handler
	// runtime is the cloud agent runtime face (G0 M34 D994).
	runtime *runtimeface.Handler
	log     *slog.Logger
	// reportDrift, driftEvery and driftPoll drive the drift checks
	// (drift.go).
	reportDrift DriftReporter
	// reportInventory sends each kind-mcp connection's discovery inventory
	// from the drift loop (G0 M15 D20); nil sends none.
	reportInventory       InventoryReporter
	driftEvery, driftPoll time.Duration
	// verifications, verifyEvery and verifyHintGap drive the verification
	// reads (verify.go, G0 M7).
	verifications              Verifications
	verifyEvery, verifyHintGap time.Duration
	// submitScan sends an organization scan's findings (orgscan.go, G0 M8).
	submitScan ScanSubmitter
	// status reports this replica's status (status.go, G0 M15 D10).
	status *status
}

// Handler returns the gateway's agent-facing HTTP handler: `/mcp/{connection}`
// (mcp), `/mcp-oauth/{connection}` and its metadata (mcpauth), `/hook/{connection}` (hook), `/runtime/agentcore` (runtime), `/sdk/{connection}` (sdk), `/a2a/{connection}` (a2a) and
// `/{connection}/…` (httpproxy).
func (g *Gateway) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := mcp.Path(r.URL.EscapedPath()); ok {
			g.mcp.ServeHTTP(w, r)
			return
		}
		if _, ok := mcpauth.Path(r.URL.EscapedPath()); ok && g.mcpOAuth != nil {
			g.mcpOAuth.ServeHTTP(w, r)
			return
		}
		if runtimeface.Serves(r.URL.EscapedPath()) {
			g.runtime.ServeHTTP(w, r) // G0 M34 D994: before the HTTP proxy
			return
		}
		if _, ok := hook.Path(r.URL.EscapedPath()); ok {
			g.hook.ServeHTTP(w, r)
			return
		}
		if _, ok := sdk.Path(r.URL.EscapedPath()); ok {
			g.sdk.ServeHTTP(w, r)
			return
		}
		if g.model.Serves(r.URL.EscapedPath()) {
			g.model.ServeHTTP(w, r) // G0 M25 D313: only a connection marked as a model relay (D525 L5)
			return
		}
		if _, _, ok := a2aface.Path(r.URL.EscapedPath()); ok {
			g.a2a.ServeHTTP(w, r)
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
	// ReportCircuitReason tells the server a connection's circuit opened for
	// a reason (stripe_livemode, G0 M14 D76).
	ReportCircuitReason dispatch.ReasonReporter
	// ReportDrift tells the server an upstream MCP tool drifted (HR-081);
	// nil reports nothing.
	ReportDrift DriftReporter
	// ReportPageCompare tells the server of a cloaking compare mismatch (G0
	// M33 D986); nil turns the compare off.
	ReportPageCompare browsercompare.Reporter
	// ReportInventory tells the server what each kind-mcp connection's upstream
	// server lists (F352, G0 M15 D20); nil reports nothing.
	ReportInventory InventoryReporter
	// Verifications claims and reports verification tasks (G0 M7); nil
	// makes no verification reads.
	Verifications Verifications
	// Connectors runs the connector connections; nil when they are not
	// enabled.
	Connectors *connectors.Supervisor
	// ReportFacts reports what the gateway reads from GitHub before a
	// decision, as the connection's fact provider (G0 M8 decision 5); nil
	// reads nothing.
	ReportFacts dispatch.FactReporter
	// ReportRevocation tells the server a token minted for a read or a scan
	// could not be revoked (ADR-0021 item 6); nil only logs it.
	ReportRevocation dispatch.RevocationReporter
	// ReportLocalRefusal tells the server of a secret_in_payload refusal (G0
	// M12, HR-225); nil only logs it.
	ReportLocalRefusal dispatch.LocalRefusalReporter
	// SignAgentCard asks the server to sign a rewritten A2A card (G0 M24
	// D232); nil serves cards unsigned.
	SignAgentCard a2aface.SignCard
	// SubmitScan sends an organization scan's findings to the server (G0 M8,
	// HR-209); nil submits none.
	SubmitScan ScanSubmitter
	// ReportStatus sends a status report (G0 M15 D10); nil sends none.
	ReportStatus StatusReporter
	// MCPState keeps the MCP face's holds, tasks and sessions on the server
	// (G0 M15 D14); nil keeps them in this process's memory.
	MCPState mcp.StateClient
	// ModelCalls asks the server about each model face call (G0 M25 D313);
	// nil refuses every one.
	ModelCalls modelface.Control
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
	store.Limits = cfg.CEL
	k.OnConfig(store.Changed)
	d := Deps{
		Org: id.Org.String(), GatewayID: id.Gateway.String(), Authority: ctl.Authority,
		JWKSURL: ctl.BaseURL() + "/.well-known/pantherclaw/jwks.json", JWKSClient: ctl.HTTPClient(),
		Containment: k, Configuration: store, Run: []func(context.Context) error{ctl.Run, k.Run, store.Run},
		ReportCircuit: func(ctx context.Context, conn string, unknown, total int32) error {
			_, err := ctl.Gateway.ReportCircuit(ctx, &pb.ReportCircuitRequest{ConnectionId: conn, UnknownCount: unknown, TotalCount: total})
			return err
		},
		ReportCircuitReason: func(ctx context.Context, conn, reason string) error {
			_, err := ctl.Gateway.ReportCircuit(ctx, &pb.ReportCircuitRequest{ConnectionId: conn, Reason: reason})
			return err
		},
		ReportDrift: func(ctx context.Context, conn string, d dispatch.Drift) error {
			_, err := ctl.Gateway.ReportDrift(ctx, driftRequest(conn, d))
			return err
		},
		ReportPageCompare: func(ctx context.Context, r browsercompare.Report) error {
			_, err := ctl.Gateway.ReportPageCompare(ctx, pageCompareRequest(r))
			return err
		},
		ReportInventory: func(ctx context.Context, conn string, inv dispatch.Inventory) error {
			_, err := ctl.Gateway.ReportInventory(ctx, inventoryRequest(conn, inv))
			return err
		},
		Verifications: controlVerifications{ctl},
		ReportFacts: func(ctx context.Context, conn string, obs []*pb.FactObservation) error {
			_, err := ctl.Gateway.ReportFacts(ctx, &pb.ReportFactsRequest{ConnectionId: conn, Observations: obs})
			return err
		},
		SubmitScan: controlScans{ctl}.submit,
		SignAgentCard: func(ctx context.Context, conn string, card []byte) ([]byte, []byte, error) {
			res, err := ctl.Gateway.SignAgentCard(ctx, &pb.SignAgentCardRequest{ConnectionId: conn, Card: card})
			if err != nil {
				return nil, nil, err
			}
			return res.GetSignedCard(), res.GetKeys(), nil
		},
		ReportStatus: func(ctx context.Context, r *pb.ReportStatusRequest) (int32, error) {
			res, err := ctl.Gateway.ReportStatus(ctx, r)
			return res.GetNextReportSeconds(), err
		},
		MCPState:   ctl.Gateway,
		ModelCalls: controlModelCalls{ctl},
		ReportRevocation: func(ctx context.Context, conn, purpose string, a broker.Access) error {
			req := &pb.ReportRevocationFailureRequest{
				ConnectionId: conn, Purpose: purpose, InstallationId: a.Installation, Repository: a.Repository,
			}
			if !a.Expires.IsZero() {
				req.ExpireTime = timestamppb.New(a.Expires)
			}
			_, err := ctl.Gateway.ReportRevocationFailure(ctx, req)
			return err
		},
		ReportLocalRefusal: func(ctx context.Context, conn, code, operation, run string, detail dispatch.RefusalDetail) error {
			req := &pb.ReportLocalRefusalRequest{ConnectionId: conn, Code: code, Operation: operation, RunId: run, QuestionSha256: detail.QuestionSHA256}
			if detail.ElicitationReason != "" {
				req.ElicitationReason = &detail.ElicitationReason
			}
			_, err := ctl.Gateway.ReportLocalRefusal(ctx, req)
			return err
		},
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
	if cfg.Connectors.Enabled {
		sup, err := connectors.New(ctx, docker.New(docker.CLI{}), cfg.Connectors, store, log)
		if err != nil {
			return nil, err
		}
		d.Connectors = sup.WithReporter(func(ctx context.Context, r *pb.ReportConnectorStateRequest) error {
			_, err := ctl.Gateway.ReportConnectorState(ctx, r)
			return err
		})
		d.Run = append(d.Run, sup.Run)
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
		Containment: d.Containment, AllowedPrefixes: prefixes, ReportCircuit: d.ReportCircuit, ReportCircuitReason: d.ReportCircuitReason, Log: log,
		Approvers:   proof.NewPinned(cfg.Approvals.ApproverKeysFile, d.Org),
		ReportFacts: d.ReportFacts, FactTimeout: cfg.GitHub.FactTimeout.D(), ReportRevocation: d.ReportRevocation, ReportLocalRefusal: d.ReportLocalRefusal,
		GitHubAPIURL: cfg.GitHub.APIURL,
	}
	if d.Connectors != nil {
		o.Connectors = d.Connectors
	}
	if d.Broker != nil {
		o.Broker = d.Broker
	}
	if o.Content, err = contentScanner(cfg, log); err != nil {
		return nil, err
	}
	var g *Gateway
	// A call's own check reports drift at once, as the loop's does. Calls
	// start only once g is set.
	o.OnDrift = func(ctx context.Context, connection string, dr dispatch.Drift) { g.drifted(ctx, connection, dr) }
	engine, err := dispatch.New(o)
	if err != nil {
		return nil, err
	}
	if s, ok := d.Configuration.(interface{ Subscribe(func(*control.Config)) }); ok {
		s.Subscribe(engine.Configured) // D105: pools of gone connections close
	}
	if d.Connectors != nil {
		d.Connectors.WithEgress(engine)
	}
	if log == nil {
		log = pclog.Discard()
	}
	g = &Gateway{
		run: d.Run, containment: d.Containment, config: d.Configuration, broker: d.Broker, engine: engine,
		http:    httpproxy.New(engine, d.Configuration, cfg.PublicURL, log),
		mcp:     mcp.New(engine, d.Configuration, cfg.PublicURL, log),
		hook:    hook.New(engine, d.Configuration, cfg.PublicURL, log),
		runtime: runtimeface.New(engine, d.Configuration, cfg.PublicURL, log),
		sdk:     sdk.New(engine, d.Configuration, cfg.PublicURL, log),
		a2a:     a2aface.New(engine, d.Configuration, a2aPeer, cfg.PublicURL, log).WithCardSigner(d.SignAgentCard),
		model:   modelface.New(engine, d.ModelCalls, d.Configuration, cfg.PublicURL, log),
		log:     log, reportDrift: d.ReportDrift, reportInventory: d.ReportInventory, driftEvery: DriftEvery, driftPoll: driftPoll,
		verifications: d.Verifications, verifyEvery: VerifyEvery, verifyHintGap: verifyHintGap,
		submitScan: d.SubmitScan,
		status:     newStatus(d.ReportStatus),
	}
	g.mcpOAuth = mcpauth.New(g.mcp, d.Configuration, cfg.PublicURL)
	// The cloaking compare (G0 M33 D986, HR-759): off while
	// browser_compare.plain_user_agent is unset. Its fetches go through an
	// egress client of their own (HR-070..072), redirects followed by hand.
	if c := browsercompare.New(browsercompare.Options{
		PlainUserAgent: cfg.BrowserCompare.PlainUserAgent, Report: d.ReportPageCompare, Log: log,
		Client: httpx.NewEgressClient(httpx.EgressConfig{Timeout: browsercompare.FetchTimeout}),
	}); c != nil {
		g.hook.WithBrowserCompare(c)
		g.run = append(g.run, c.Run)
	}
	if d.MCPState != nil {
		var sealer mcp.Sealer
		if d.Broker != nil {
			sealer = d.Broker.key
		}
		g.mcp.WithServerState(d.MCPState, sealer, d.Org, d.GatewayID)
		// A2A task and context ownership too (G0 M19 D211).
		if sealer != nil {
			g.a2a.WithServerState(d.MCPState, sealer, d.Org, d.GatewayID)
		}
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
	eg.Go(func() error { return g.watchA2ACards(ctx) })
	eg.Go(func() error { return g.watchVerifications(ctx) })
	eg.Go(func() error { return g.watchStatus(ctx) })
	eg.Go(func() error { return g.warnUnsharedTasks(ctx) })
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

// Contained is the containment check every dispatch makes first (HR-010):
// nil when the gateway asks the Authority, or why it refuses every
// dispatch on its own now (control.ErrKillSwitch, ErrRevoked, ErrStale).
func (g *Gateway) Contained() error {
	_, err := g.containment.Check()
	return err
}

// Epoch is the containment epoch the gateway's check holds now, 0 while
// its view is stale. It reads only: a permit from an older epoch is
// refused as stale either way (PN-011.3 measures when this catches up).
func (g *Gateway) Epoch() int64 {
	e, _ := g.containment.Check()
	return e
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

// pageCompareRequest is the ReportPageCompare request of one mismatch.
func pageCompareRequest(r browsercompare.Report) *pb.ReportPageCompareRequest {
	return &pb.ReportPageCompareRequest{
		ConnectionId: r.Connection, RunId: r.Run, TransactionId: r.Transaction, Host: r.Host, PathSha256: r.PathSHA256,
		AgentStatus: r.AgentStatus, PlainStatus: r.PlainStatus, AgentBytes: r.AgentBytes, PlainBytes: r.PlainBytes,
		SimilarityPermille: r.SimilarityPermille,
	}
}

// maxDriftDescription is the most of an observed tool description a drift
// report carries (ReportDriftRequest.observed_description).
const maxDriftDescription = 8192

// driftRequest is the ReportDrift request of one drifted tool of conn. A
// drift a call's own check found names that call's transaction; the server
// takes the run from its own row of it, never from the gateway (HR-665).
func driftRequest(conn string, d dispatch.Drift) *pb.ReportDriftRequest {
	req := &pb.ReportDriftRequest{
		ConnectionId: conn, Tool: d.Tool, ExpectedDigest: d.Expected, ObservedDigest: d.Observed, TransactionId: d.Transaction,
	}
	req.ObservedDescription, req.ObservedDescriptionTruncated, req.ObservedDescriptionSha256 = driftDescription(d.Description)
	return req
}

// driftDescription bounds an observed description to whole UTF-8
// characters within maxDriftDescription bytes (G0 M10 D47), and says
// whether it cut it and the SHA-256 of the whole description (D59 M8).
func driftDescription(d *string) (*string, bool, string) {
	if d == nil {
		return nil, false, ""
	}
	sum := sha256.Sum256([]byte(*d))
	s := strings.ToValidUTF8(*d, "")
	truncated := len(s) > maxDriftDescription
	if truncated {
		s = s[:maxDriftDescription]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return &s, truncated, "sha256:" + hex.EncodeToString(sum[:])
}
