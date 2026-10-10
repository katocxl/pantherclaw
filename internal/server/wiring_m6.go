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
	// verifications are leased to gateways over this listener (G0 M7);
	// nil leaves the RPCs unimplemented.
	verifications gatewaysrpc.Verifications
	// rpID is the WebAuthn relying party approver keys are exported for
	// (HR-038); "" when security keys are off.
	rpID string
}

// newM6 builds the M6 services; notify (M5 notifications) may be nil.
func newM6(cfg *Config, pool *db.Pool, reg *keys.Registry, notify rapp.Notifier, log *slog.Logger) (*m6Services, error) {
	authority, err := ca.New(reg)
	if err != nil {
		return nil, err
	}
	return &m6Services{
		reg: reg, ca: authority, gateways: gwapp.New(pool, authority, cfg.GatewayAPI.URL, clock.System{}), hub: gwapp.NewHub(pool, log),
		response:    rapp.New(pool, notify, cfg.Auth.PublicURL),
		connections: capp.New(pool, notify, cfg.Auth.PublicURL, cfg.GatewayAPI.URL),
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
	pantherclawv1connect.RegisterGatewayAdminServiceHandler(rs, gatewaysrpc.NewAdmin(m.gateways).WithRPID(m.rpID))
	pantherclawv1connect.RegisterGatewayServiceHandler(rs, gatewaysrpc.NewGateway(m.gateways))
	pantherclawv1connect.RegisterContainmentServiceHandler(rs, responserpc.New(m.response))
	pantherclawv1connect.RegisterConnectionServiceHandler(rs, connectionsrpc.New(m.connections, m.credentials))
}

// mountPages adds the emergency-stop page, the only place the kill switch
// is engaged or restored (G0 M6 decision 2).
func (m *m6Services) mountPages(web *webhttp.Handler) {
	if m != nil {
		web.WithContainment(m.response)
	}
}

// gatewayHandler is the gateway listener's handler: AuthorityService and
// GatewayService only, every call authenticated by its client certificate
// (HR-181, HR-020).
func (m *m6Services) gatewayHandler(svc *authority.Service, log *slog.Logger) (http.Handler, error) {
	rs, err := rpc.NewServer(rpc.Options{Logger: log, Authenticate: gatewaysrpc.Authenticator(m.gateways, procedurePermissions)})
	if err != nil {
		return nil, err
	}
	pantherclawv1connect.RegisterAuthorityServiceHandler(rs, authority.NewHandler(svc))
	gw := gatewaysrpc.NewGateway(m.gateways).WithHub(m.hub).WithCircuits(m.connections).WithDrifts(m.connections)
	if m.verifications != nil {
		gw = gw.WithVerifications(m.verifications)
	}
	pantherclawv1connect.RegisterGatewayServiceHandler(rs, gw)
	mux := http.NewServeMux()
	rpc.Mount(mux, rs)
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

// gatewayTLS is the gateway listener's TLS profile: TLS 1.3, hybrid key
// exchange preferred, and a client certificate that chains to the internal
// CA required on every connection.
func (m *m6Services) gatewayTLS(names []string) *tls.Config {
	certs := &listenerCerts{ca: m.ca, names: names, clk: clock.System{}}
	conf := httpx.ServerTLSConfig(tls.Certificate{})
	conf.Certificates = nil
	conf.GetCertificate = certs.get
	conf.ClientAuth = tls.RequireAndVerifyClientCert
	conf.ClientCAs = m.ca.Pool()
	return conf
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
	srv, err := httpx.NewServer(httpx.ServerConfig{Addr: cfg.GatewayAPI.Addr, Handler: handler, TLS: m.gatewayTLS(cfg.GatewayAPI.Hostnames), Logger: log})
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
	g.Go(func() error { return m.hub.Run(ctx) })
	g.Go(func() error {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		return srv.Shutdown(sctx)
	})
	return nil
}
