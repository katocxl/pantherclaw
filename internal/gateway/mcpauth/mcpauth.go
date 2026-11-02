// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mcpauth is the OAuth route of the gateway's MCP face, for
// standard MCP clients (G0 M26 D402, D408; MCP 2026-07-28 authorization):
//
//	GET  /.well-known/oauth-protected-resource/mcp-oauth/{connection}
//	     protected resource metadata (RFC 9728), naming the org's
//	     authorization server
//	POST /mcp-oauth/{connection}
//	     the MCP face, with an MCP access token (pap-mcp+jwt) as a bearer
//
// The route exists only while the org's MCP authorization is on: otherwise
// both are 404. A request without a bearer token is answered 401 with a
// WWW-Authenticate header pointing at the metadata (RFC 9728 §5.1). A
// bearer token is never checked here: the gateway forwards it to the
// Authority with no proof, for the request URL on this route, and the
// Authority verifies it on every call, choosing bearer mode from the
// token's type alone (HR-021, HR-626). A PAP/1 Authorization header or
// proof on this route is refused, and the PAP/1 routes never take a bearer
// token. The run is the one the token names; the Authority refuses any
// other.
package mcpauth

import (
	"encoding/base64"
	"encoding/json/v2"
	"net/http"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/mcp"
	iddomain "github.com/katocxl/pantherclaw/internal/idaccess/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Paths of the route.
const (
	ResourcePrefix = iddomain.ResourcePath
	MetadataPrefix = "/.well-known/oauth-protected-resource" + iddomain.ResourcePath
)

// maxToken bounds a bearer token.
const maxToken = 8192

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves the OAuth route.
type Handler struct {
	mcp       http.Handler
	config    Configuration
	publicURL string
}

// New returns the route over the MCP face. publicURL is the gateway's base
// URL: every resource identifier is under it.
func New(face http.Handler, config Configuration, publicURL string) *Handler {
	return &Handler{mcp: face, config: config, publicURL: strings.TrimSuffix(publicURL, "/")}
}

// Path reports whether a request path is the route's, and the connection
// it names.
func Path(escapedPath string) (string, bool) {
	for _, p := range []string{ResourcePrefix, MetadataPrefix} {
		if name, ok := strings.CutPrefix(escapedPath, p); ok {
			return name, name != "" && !strings.Contains(name, "/")
		}
	}
	return "", false
}

func (h *Handler) resource(conn string) string { return iddomain.ResourceURL(h.publicURL, conn) }

func (h *Handler) metadataURL(conn string) string { return h.publicURL + MetadataPrefix + conn }

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, ok := Path(r.URL.EscapedPath())
	cfg := h.config.Current()
	if !ok || cfg == nil || cfg.McpIssuer == "" || cfg.ByName[conn] == nil {
		http.NotFound(w, r)
		return
	}
	if strings.HasPrefix(r.URL.EscapedPath(), MetadataPrefix) {
		h.metadata(w, r, conn, cfg.McpIssuer)
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" || len(token) > maxToken || len(r.Header.Values("Authorization")) != 1 {
		h.challenge(w, conn, "")
		return
	}
	if r.Header.Get(dispatch.HeaderProof) != "" {
		// A bearer token carries no PAP/1 proof (D408).
		h.challenge(w, conn, "invalid_request")
		return
	}
	fwd := r.Clone(mcp.WithOAuth(r.Context(), h.resource(conn)))
	fwd.Header.Set("Authorization", "PAP "+token)
	fwd.Header.Del(dispatch.HeaderProof)
	fwd.Header.Del(dispatch.HeaderRunID)
	if run := runOf(token); run != "" {
		fwd.Header.Set(dispatch.HeaderRunID, run)
	}
	fwd.URL.Path, fwd.URL.RawPath = "/mcp/"+conn, ""
	h.mcp.ServeHTTP(&challenger{ResponseWriter: w, h: h, conn: conn}, fwd)
}

// metadata serves the RFC 9728 protected resource metadata.
func (h *Handler) metadata(w http.ResponseWriter, r *http.Request, conn, issuer string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	b, err := json.Marshal(map[string]any{
		"resource":                 h.resource(conn),
		"authorization_servers":    []string{issuer},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            conn,
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}

// challenge answers 401 with the RFC 6750 §3 challenge and the metadata
// URL (RFC 9728 §5.1).
func (h *Handler) challenge(w http.ResponseWriter, conn, errCode string) {
	w.Header().Set("WWW-Authenticate", h.wwwAuthenticate(conn, errCode))
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (h *Handler) wwwAuthenticate(conn, errCode string) string {
	v := `Bearer resource_metadata="` + h.metadataURL(conn) + `"`
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	return v
}

// challenger adds the challenge to the MCP face's refusals: a 401 is an
// invalid token, a 403 a token whose scope does not cover the call.
type challenger struct {
	http.ResponseWriter
	h     *Handler
	conn  string
	wrote bool
}

func (c *challenger) WriteHeader(status int) {
	if !c.wrote {
		c.wrote = true
		switch status {
		case http.StatusUnauthorized:
			c.Header().Set("WWW-Authenticate", c.h.wwwAuthenticate(c.conn, "invalid_token"))
		case http.StatusForbidden:
			c.Header().Set("WWW-Authenticate", c.h.wwwAuthenticate(c.conn, "insufficient_scope"))
		}
	}
	c.ResponseWriter.WriteHeader(status)
}

func (c *challenger) Write(b []byte) (int, error) {
	if !c.wrote {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

// Flush passes a streamed response through.
func (c *challenger) Flush() {
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap gives http.ResponseController the underlying writer.
func (c *challenger) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// runOf reads, WITHOUT verifying, the run an MCP access token names: the
// call's run, which the Authority checks is the token's.
func runOf(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var c struct {
		PAP struct {
			Run string `json:"run"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return ""
	}
	run, err := ids.ParseUUID(c.PAP.Run)
	if err != nil || run.IsZero() {
		return ""
	}
	return run.String()
}
