// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package hostingrpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/gateways/adapters/gatewaysrpc"
	"github.com/katocxl/pantherclaw/internal/gateways/ca"
	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR500_AHostCertificateReachesOnlyTheAgentService: the gateway
// listener's gateway authenticator refuses every HostingAgentService
// procedure, the host authenticator refuses every other procedure and any
// call without a host identity, and a host certificate never yields a
// gateway identity (or a gateway certificate a host identity).
//
// Covers: PN-010.4
func TestHR500_AHostCertificateReachesOnlyTheAgentService(t *testing.T) {
	perms := map[string]td.Permission{
		pantherclawv1connect.GatewayServiceGetConfigurationProcedure: td.PermGatewaySync,
	}
	for p, perm := range AgentProcedures {
		perms[p] = perm
		if perm.Gateway() {
			t.Fatalf("%s needs a gateway permission", p)
		}
	}
	gwAuth := gatewaysrpc.Authenticator(nil, perms)
	for p := range AgentProcedures {
		if _, err := gwAuth(context.Background(), nil, connect.Spec{Procedure: p}); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("the gateway authenticator admits %s: %v", p, err)
		}
	}
	hostAuth := HostAuthenticator(nil)
	for _, p := range []string{
		pantherclawv1connect.GatewayServiceGetConfigurationProcedure,
		pantherclawv1connect.AuthorityServiceAuthorizeProcedure,
		pantherclawv1connect.HostedGatewayServiceRequestHostedGatewayProcedure,
		pantherclawv1connect.HostedGatewayIdentityServiceIssueServerCertificateProcedure,
	} {
		if _, err := hostAuth(context.Background(), nil, connect.Spec{Procedure: p}); connect.CodeOf(err) != connect.CodePermissionDenied {
			t.Errorf("the host authenticator admits %s: %v", p, err)
		}
	}
	if _, err := hostAuth(context.Background(), nil, connect.Spec{Procedure: pantherclawv1connect.HostingAgentServiceListAssignmentsProcedure}); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Errorf("no host identity: %v", err)
	}

	host := &x509.Certificate{URIs: []*url.URL{ca.HostIdentity{Host: ids.NewV7(), Cert: ids.NewV7()}.URI()}}
	gw := &x509.Certificate{URIs: []*url.URL{ca.Identity{Org: ids.New[ids.Org](), Gateway: ids.NewV7(), Cert: ids.NewV7()}.URI()}}
	seen := func(wrap func(http.Handler) http.Handler, cert *x509.Certificate) (gateway, hostID bool) {
		h := wrap(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			_, gateway = gatewaysrpc.IdentityFrom(r.Context())
			_, hostID = HostFrom(r.Context())
		}))
		r := httptest.NewRequest(http.MethodPost, "/", nil)
		r.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{cert}}}
		h.ServeHTTP(httptest.NewRecorder(), r)
		return gateway, hostID
	}
	if g, h := seen(gatewaysrpc.TLSIdentity, host); g || h {
		t.Error("a host certificate became a gateway identity")
	}
	if g, h := seen(HostIdentity, gw); g || h {
		t.Error("a gateway certificate became a host identity")
	}
	if _, h := seen(HostIdentity, host); !h {
		t.Error("a host certificate was not read")
	}
}
