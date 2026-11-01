// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"connectrpc.com/connect/v2"
	"golang.org/x/sync/errgroup"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/connections/adapters/connectionsrpc"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	"github.com/katocxl/pantherclaw/internal/gateways/adapters/gatewaysrpc"
	gwapp "github.com/katocxl/pantherclaw/internal/gateways/app"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	hostingapp "github.com/katocxl/pantherclaw/internal/hosting/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
	"github.com/katocxl/pantherclaw/internal/response/adapters/responserpc"
	rapp "github.com/katocxl/pantherclaw/internal/response/app"
)

// m6Services are the M6 services (G0 M6): the internal CA, gateway identity,
// the kill switch and connections.
type m6Services struct {
	reg      *keys.Registry
	ca       *ca.Authority
	gateways *gwapp.Service
	// hub feeds the containment streams (HR-010).
	hub *gwapp.Hub
	// response is the kill switch (HR-113).
	response *rapp.Service
	// connections are the targets gateways serve (HR-183).
	connections *capp.Service
	// credentials hold sealed credentials (HR-182).
	credentials *credapp.Service
	// hosting is the PantherClaw-hosted gateways (G0 M19 D203); nil serves none.
	hosting *hostingapp.Service
	// verifications are leased to gateways over this listener (G0 M7);
	// nil leaves the RPCs unimplemented.
	verifications gatewaysrpc.Verifications
	// facts takes what gateways read as connections' fact providers (G0 M8);
	// nil leaves ReportFacts unimplemented.
	facts gatewaysrpc.Facts
	// scans takes a gateway's organization scan findings on the gateway
	// listener (G0 M8, HR-209); nil leaves SubmitScanFindings unserved there.
	scans pantherclawv1connect.AgentServiceHandler
	// cards signs the A2A cards gateways serve (G0 M24 D232).
	cards gatewaysrpc.CardSigner
	// rpID is the WebAuthn relying party approver keys are exported for
	// (HR-038); "" when security keys are off.
	rpID string
	// hold is the operator's maintenance hold: the gateway listener refuses
	// every procedure (G0 M13 D26, HR-379).
	hold bool
	// fleet serves the fleet policy, view and sweep (G0 M18 D151).
	fleet *gwapp.Fleet
}

// newM6 builds the M6 services; notify (M5 notifications) may be nil.
func newM6(cfg *Config, pool *db.Pool, reg *keys.Registry, notify rapp.Notifier, log *slog.Logger) (*m6Services, error) {
	hosted, err := cfg.pantherClawHosted()
	if err != nil {
		return nil, err
	}
	authority, err := ca.New(reg)
	if err != nil {
		return nil, err
	}
	return &m6Services{
		reg: reg, ca: authority, gateways: gwapp.New(pool, authority, cfg.GatewayAPI.URL, clock.System{}).WithPantherClawHosted(hosted),
		hub:         gwapp.NewHub(pool, log),
		response:    rapp.New(pool, notify, cfg.Auth.PublicURL),
		connections: capp.New(pool, notify, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).WithPantherClawHosted(hosted),
		credentials: credapp.New(pool, notify),
		rpID:        cfg.webAuthnRPID(),
	}, nil
}

// registerPublic adds gateway administration, gateway enrollment, the
// containment state and connections to the public API. GatewayService's
// other procedures declare gateway permissions, which the public API never
// grants (HR-181).
func (m *m6Services) registerPublic(rs *connect.Server) {
	if m == nil {
		return
	}
	pantherclawv1connect.RegisterGatewayAdminServiceHandler(rs, gatewaysrpc.WithFleet(gatewaysrpc.NewAdmin(m.gateways).WithRPID(m.rpID), m.fleet))
	pantherclawv1connect.RegisterGatewayServiceHandler(rs, gatewaysrpc.NewGateway(m.gateways))
	pantherclawv1connect.RegisterContainmentServiceHandler(rs, responserpc.New(m.response))
	pantherclawv1connect.RegisterConnectionServiceHandler(rs, connectionsrpc.New(m.connections, m.credentials))
	m.registerHostingPublic(rs)
}

// mountPages adds the emergency-stop page, the only place the kill switch
// is engaged or restored (G0 M6 decision 2).
func (m *m6Services) mountPages(web *webhttp.Handler) {
	if m != nil {
		web.WithContainment(m.response)
	}
}

// gatewayHandler is the gateway listener's handler: AuthorityService and
// GatewayService, and AgentService.SubmitScanFindings for a gateway's
// organization scan (G0 M8), every call authenticated by its client
// certificate (HR-181, HR-020).
func (m *m6Services) gatewayHandler(svc *authority.Service, log *slog.Logger) (http.Handler, error) {
	rs, err := rpc.NewServer(rpc.Options{Logger: log, Authenticate: holdAuthenticator(m.hold, heldOnGatewayListener,
		gatewaysrpc.Authenticator(m.gateways, gatewayListenerPermissions()))})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(svc))
	gw := gatewaysrpc.NewGateway(m.gateways).WithHub(m.hub).WithCircuits(m.connections).WithDrifts(m.connections).WithInventories(m.connections).WithRevocations(m.connections).WithLocalRefusals(m.connections)
	if m.verifications != nil {
		gw = gw.WithVerifications(m.verifications)
	}
	if m.facts != nil {
		gw = gw.WithFacts(m.facts)
	}
	if m.cards != nil {
		gw = gw.WithCardSigner(m.cards)
	}
	pantherclawv1connect.RegisterGatewayServiceHandler(rs, gw)
	if m.scans != nil {
		pantherclawv1connect.RegisterAgentServiceHandler(rs, m.scans)
	}
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
	if err := m.mountHosting(mux, log); err != nil {
		return nil, err
	}
	// Gateways verify permits with the JWKS, fetched here over mTLS.
	mux.HandleFunc("GET /.well-known/pantherclaw/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		b, err := m.reg.JWKS()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", "private, max-age=60")
		_, _ = w.Write(b)
	})
	return gatewaysrpc.TLSIdentity(gatewaysrpc.StreamDeadlines(mux)), nil
}

// listenerCerts serves the gateway listener's own certificate from the
// internal CA: valid 7 days, reissued (with a new key) after a day.
type listenerCerts struct {
	ca    *ca.Authority
	names []string
	clk   clock.Clock

	mu     sync.Mutex
	cert   *tls.Certificate
	issued time.Time
}

const listenerReissue = 24 * time.Hour

func (l *listenerCerts) get(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clk.Now()
	if l.cert != nil && now.Sub(l.issued) < listenerReissue {
		return l.cert, nil
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	iss, err := l.ca.IssueServer(pub, l.names, now)
	if err != nil {
		return nil, err
	}
	l.cert = &tls.Certificate{Certificate: [][]byte{iss.DER}, PrivateKey: priv}
	l.issued = now
	return l.cert, nil
}

// gatewayTLS is the gateway listener's TLS profile: a link between
// PantherClaw components (TLS 1.3 and a hybrid post-quantum key exchange
// only, the negotiated group logged; HR-395), and a client certificate that
// chains to the internal CA required on every connection.
func (m *m6Services) gatewayTLS(names []string, log *slog.Logger) *tls.Config {
	certs := &listenerCerts{ca: m.ca, names: names, clk: clock.System{}}
	conf := httpx.ServerTLSConfig(tls.Certificate{})
	conf.Certificates = nil
	conf.GetCertificate = certs.get
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	conf.ClientCAs = m.ca.Pool()
	return httpx.ComponentLinkTLS(conf, "gateway-api", log)
}

// serveGateways starts the gateway listener when gateway_api.addr is set.
func (m *m6Services) serveGateways(ctx context.Context, g *errgroup.Group, cfg *Config, svc *authority.Service, log *slog.Logger,
	onStart func(addr string),
) error {
	if m == nil || cfg.GatewayAPI.Addr == "" {
		return nil
	}
	handler, err := m.gatewayHandler(svc, log)
	if err != nil {
		return err
	}
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: cfg.GatewayAPI.Addr, Handler: handler, TLS: m.gatewayTLS(cfg.GatewayAPI.Hostnames, log), Logger: log})
	if err != nil {
		return err
	}
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.GatewayAPI.Addr)
	if err != nil {
		return fmt.Errorf("server: gateway listener: %w", err)
	}
	if onStart != nil {
		onStart(ln.Addr().String())
	}
	log.InfoContext(ctx, "server.gateway_listener", slog.String("addr", ln.Addr().String()),
		slog.String("ca_sha256", ca.Fingerprint(m.ca.Certificate())))
	g.Go(func() error {
		if err := srv.ServeTLS(ln, "", ""); !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	})
	// The containment streams' early wake-ups; stopping it ends the streams.
	// Its notifications also reach the certificate cache (G0 M19 D201).
	m.hub.ForgetOnNotify(m.gateways)
	g.Go(func() error { return m.hub.Run(ctx) })
	g.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return srv.Shutdown(sctx)
	})
	return nil
}
