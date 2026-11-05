// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	credentials "github.com/katocxl/pantherclaw/internal/credentials/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/broker"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/saascollect"
	"github.com/katocxl/pantherclaw/internal/saasdiscovery/domain"
)

// ScanSaaS reads the agents of a SaaS tenant through a connection (G0 M26
// D407) until ctx ends: GET requests to the connection's own host, under the
// lease, with a token minted for this scan or the connection's static key.
// The credential's bytes stay in this function. An error means the credential
// could not be used at all.
func (e *Engine) ScanSaaS(ctx context.Context, conn *control.Connection, source, tenant string) (saascollect.Result, error) {
	c, err := e.client(conn)
	if err != nil {
		return saascollect.Result{}, err
	}
	base := strings.TrimSuffix(conn.GetBaseUrl(), "/")
	switch source {
	case domain.SourceCopilotStudio:
		tok, err := e.clientToken(ctx, conn)
		if err != nil {
			return saascollect.Result{}, err
		}
		defer tok.Clear()
		return saascollect.CopilotStudio(ctx, saasGetter(base, c, tok.Place), tenant), nil
	case domain.SourceChatGPTEnterprise:
		plain, err := e.openStatic(ctx, conn)
		if err != nil {
			return saascollect.Result{}, err
		}
		defer clear(plain)
		place := func(req *http.Request) error { return placeCredential(conn, req, plain) }
		return saascollect.ChatGPTEnterprise(ctx, saasGetter(base, c, place), tenant), nil
	case domain.SourceVertexAgentEngine:
		_, location, ok := domain.VertexTenant(tenant)
		if !ok || !vertexHostFits(base, location) {
			return saascollect.Result{}, errRuntimeTenant
		}
		tok, err := e.serviceAccountToken(ctx, conn)
		if err != nil {
			return saascollect.Result{}, err
		}
		defer tok.Clear()
		return saascollect.VertexAgentEngine(ctx, saasGetter(base, c, tok.Place), tenant), nil
	case domain.SourceAzureFoundry:
		// The connection's base URL is the project endpoint: it must be
		// this tenant's project (D997a).
		u, err := url.Parse(base)
		if err != nil || u.Path != "/api/projects/"+tenant {
			return saascollect.Result{}, errRuntimeTenant
		}
		tok, err := e.clientToken(ctx, conn)
		if err != nil {
			return saascollect.Result{}, err
		}
		defer tok.Clear()
		return saascollect.Foundry(ctx, saasGetter(base, c, tok.Place), tenant), nil
	case domain.SourceAWSAgentCore:
		return e.scanAgentCore(ctx, conn, c, base, tenant)
	}
	return saascollect.Result{}, saascollect.ErrSource
}

// errRuntimeTenant refuses a runtime scan whose tenant is not the
// connection's: another AWS account than the sealed role's, a Vertex
// location another regional host serves, or another Foundry project than
// the base URL's (G0 M34 D997a).
var errRuntimeTenant = errors.New("dispatch: the scan's tenant is not the connection's")

// agentCoreList is the package operation the AgentCore collector reads
// with (D993a).
const agentCoreList = "agentcore.runtimes.list"

// scanAgentCore reads the account's agent runtimes: one session, narrowed
// to the package's ListAgentRuntimes, signs every page. The tenant must be
// the sealed role's account; the region is the credential's.
func (e *Engine) scanAgentCore(ctx context.Context, conn *control.Connection, c *egress.Client, base, tenant string) (saascollect.Result, error) {
	def, ok := conn.Package.Definition(agentCoreList)
	if !ok {
		return saascollect.Result{}, broker.ErrAWSAction
	}
	plain, err := e.openCredential(ctx, conn)
	if err != nil {
		return saascollect.Result{}, err
	}
	a, err := credentials.DecodeAWSSigV4(plain)
	clear(plain)
	if err != nil {
		return saascollect.Result{}, err
	}
	account, region := a.Account(), a.Region
	a.Clear()
	if account != tenant {
		return saascollect.Result{}, errRuntimeTenant
	}
	s, err := e.awsSession(ctx, conn, def, actionir.Target{Type: def.Target.Type, ID: tenant, Account: tenant})
	if err != nil {
		return saascollect.Result{}, err
	}
	defer s.Clear()
	post := func(ctx context.Context, path string, body []byte) (egress.Response, error) {
		u, err := url.Parse(base + path)
		if err != nil {
			return egress.Response{}, err
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodPost, URL: u, Body: body})
		if err != nil {
			return egress.Response{}, err
		}
		if err := s.Sign(req, body, time.Now()); err != nil {
			return egress.Response{}, err
		}
		return c.Do(req)
	}
	return saascollect.AgentCore(ctx, post, tenant, region), nil
}

// vertexHostFits reports whether a Vertex base URL can serve location: a
// regional host must be location's; any other host (a simulator) is taken
// as it is, its egress rules already bound.
func vertexHostFits(base, location string) bool {
	u, err := url.Parse(base)
	if err != nil {
		return false
	}
	region, ok := strings.CutSuffix(u.Hostname(), "-aiplatform.googleapis.com")
	return !ok || region == location
}

// saasGetter reads one path through the connection's egress client with the
// credential placed.
func saasGetter(base string, c *egress.Client, place func(*http.Request) error) saascollect.Getter {
	return func(ctx context.Context, path string) (egress.Response, error) {
		u, err := url.Parse(base + path)
		if err != nil {
			return egress.Response{}, err
		}
		req, err := c.HTTPRequest(ctx, egress.Request{Method: http.MethodGet, URL: u})
		if err != nil {
			return egress.Response{}, err
		}
		if err := place(req); err != nil {
			return egress.Response{}, err
		}
		return c.Do(req)
	}
}
