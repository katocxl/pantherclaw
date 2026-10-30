// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"log/slog"
	"net/http"

	"connectrpc.com/connect/v2"
	"github.com/riverqueue/river"

	"github.com/katocxl/pantherclaw/internal/gateways/adapters/gatewaysrpc"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/hosting/adapters/hostingrpc"
	hostingapp "github.com/katocxl/pantherclaw/internal/hosting/app"
	"github.com/katocxl/pantherclaw/internal/keystore"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	pccrypto "github.com/katocxl/pantherclaw/internal/platform/crypto"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
	"github.com/katocxl/pantherclaw/internal/platform/rpc"
)

// newHosting builds the hosted gateway use cases (G0 M19 D203): requests
// are gated by edition (D212), and tokens are sealed with the org's DEK.
func newHosting(cfg *Config, pool *db.Pool, authority *ca.Authority, kp keys.KeyProvider, ents hostingapp.Entitlements) *hostingapp.Service {
	env := pccrypto.NewEnvelope(keystore.NewDEKStore(pool, kp))
	return hostingapp.New(pool, authority, env, ents, cfg.GatewayAPI.URL, clock.System{})
}

// registerHostingPublic serves HostedGatewayService on the public API: an
// org's people request, read and deprovision its hosted gateway.
func (m *m6Services) registerHostingPublic(rs *connect.Server) {
	if m == nil || m.hosting == nil {
		return
	}
	pantherclawv1connect.RegisterHostedGatewayServiceHandler(rs, hostingrpc.New(m.hosting))
}

// mountHosting adds the hosting procedures to the gateway listener's mux:
//   - HostedGatewayIdentityService behind the gateway authenticator, for a
//     hosted gateway's own server certificate (D210);
//   - HostingAgentService behind the host-certificate authenticator only
//     (HR-500), which admits nothing else, while the gateway authenticator
//     never admits a host certificate.
func (m *m6Services) mountHosting(mux *http.ServeMux, log *slog.Logger) error {
	if m == nil || m.hosting == nil {
		return nil
	}
	ids, err := rpc.NewServer(rpc.Options{Logger: log, Authenticate: holdAuthenticator(m.hold, heldOnGatewayListener,
		gatewaysrpc.Authenticator(m.gateways, gatewayListenerPermissions()))})
	if err != nil {
		return err
	}
	pantherclawv1connect.RegisterHostedGatewayIdentityServiceHandler(ids, hostingrpc.NewIdentity(m.hosting))
	rpc.Mount(mux, ids)
	hosts, err := rpc.NewServer(rpc.Options{Logger: log, Authenticate: holdAuthenticator(m.hold, heldOnGatewayListener,
		hostingrpc.HostAuthenticator(m.hosting))})
	if err != nil {
		return err
	}
	pantherclawv1connect.RegisterHostingAgentServiceHandler(hosts, hostingrpc.NewAgent(m.hosting))
	hostMux := http.NewServeMux()
	rpc.Mount(hostMux, hosts)
	mux.Handle("/"+pantherclawv1connect.HostingAgentServiceName+"/", hostingrpc.HostIdentity(hostMux))
	return nil
}

// registerM19HostingJobs adds the provisioner (D203): it creates gateways
// and seals their single-use tokens, so it needs the DEKs, not the CA.
func registerM19HostingJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, cfg *Config, pool *db.Pool, kp keys.KeyProvider,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if err := newHosting(cfg, pool, nil, kp, nil).RegisterJobs(reg, log); err != nil {
		return nil, err
	}
	return append(periodic, hostingapp.PeriodicJobs()...), nil
}
