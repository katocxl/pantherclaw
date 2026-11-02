// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"net/http"

	"connectrpc.com/connect/v2"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/oauthhttp"

	"github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1/pantherclawv1connect"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/cimd"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idaccessrpc"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/idjag"
	"github.com/katocxl/pantherclaw/internal/idaccess/adapters/mcptoken"
	idapp "github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/crypto/jws"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// IdP-native agent access (G0 M26 D400-D403, D408; H8): IdpAccessService
// files every addition as an always-held protected change, and the token
// endpoint gains the jwt-bearer grant for ID-JAGs and the authorization
// code and refresh grants of allow-listed MCP clients, whose consent page
// is a server page (webhttp). Each org that uses either has its own
// authorization server metadata. Its procedure permissions are in
// procedures_m26_idaccess.go.

// m26IdAccess is what the API builds once and the routes share.
type m26IdAccess struct {
	admin    *idapp.Admin
	exchange *idapp.Exchange
	flow     *idapp.CodeFlow
}

// newM26IdAccess builds the use cases over the API's dependencies.
func newM26IdAccess(d apiDeps) m26IdAccess {
	verifier := &idjag.Verifier{}
	admin := &idapp.Admin{Pool: d.pool, Gate: d.m11protect.gate, Discovery: verifier, PublicURL: d.publicURL}
	if d.billing != nil {
		admin.Editions = d.billing
	}
	if d.m5 != nil && d.m5.notifications != nil {
		admin.Notify = d.m5.notifications
	}
	_, runs := m11Issuance(d)
	minter := &mcptoken.Minter{Keys: mcpTokenKeys(d.reg), Issuer: d.publicURL}
	exchange := &idapp.Exchange{
		Pool: d.pool, Verifier: verifier, Runs: runs, PublicURL: d.publicURL, Clock: clock.System{}, Log: d.log, Tokens: minter,
	}
	flow := &idapp.CodeFlow{
		Pool: d.pool, Documents: &cimd.Reader{}, Runs: runs, Tokens: minter, Notify: admin.Notify,
		PublicURL: d.publicURL, Clock: clock.System{}, Log: d.log,
	}
	return m26IdAccess{admin: admin, exchange: exchange, flow: flow}
}

// mcpTokenKeys is the active mcp_tokens signer.
func mcpTokenKeys(reg *keys.Registry) mcptoken.Signer {
	return mcptoken.SignerFunc(func() (*jws.Signer, error) { return reg.Signer(keys.PurposeMcpTokens) })
}

// registerM26IdAccess serves IdpAccessService, registers its surfaces on
// the protect Gate and adds the jwt-bearer grant to the token endpoint.
func registerM26IdAccess(rs *connect.Server, d apiDeps) {
	m := newM26IdAccess(d)
	if d.m11protect.gate != nil {
		m.admin.Register(d.m11protect.gate)
	}
	pantherclawv1connect.RegisterIdpAccessServiceHandler(rs, idaccessrpc.New(m.admin))
	if d.oauth != nil {
		d.oauth.HandleGrant(idapp.GrantJWTBearer, m.exchange.JWTBearer)
		d.oauth.HandleGrant(idapp.GrantAuthorizationCode, m.flow.AuthorizationCode)
		d.oauth.HandleGrantIf(oauthhttp.GrantRefreshToken, idapp.IsRefresh, m.flow.Refresh)
		d.oauth.HandleFunc("GET /.well-known/oauth-authorization-server/orgs/{org}", orgMetadata(m.flow))
	}
	if d.web != nil {
		d.web.WithMcpConsent(m.flow)
	}
	if d.m6 != nil && d.m6.gateways != nil {
		d.m6.gateways.WithMcpIssuerBase(d.publicURL)
	}
}

// orgMetadata serves an org's authorization server metadata (RFC 8414 §3.1
// path insertion); an org that uses no IdP-native access has none.
func orgMetadata(flow *idapp.CodeFlow) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		org, err := ids.Parse[ids.Org](r.PathValue("org"))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		md, ok, err := flow.Metadata(r.Context(), org)
		switch {
		case err != nil:
			oauthhttp.WriteError(w, err)
		case !ok:
			http.NotFound(w, r)
		default:
			oauthhttp.WriteJSON(w, http.StatusOK, md)
		}
	}
}
