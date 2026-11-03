// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"net/http"
	"net/url"
	"strings"

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
	}
	return saascollect.Result{}, saascollect.ErrSource
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
