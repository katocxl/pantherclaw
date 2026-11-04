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
//
// A DPoP-bound token (RFC 9449; G0 M30 D913) comes as "Authorization: DPoP
// <token>" with one DPoP proof header. The route forwards the proof
// unchanged as PC-MCP-DPoP, removing any copy the client sent, and the
// Authority checks it. Under the Bearer scheme no proof is forwarded, so a
// bound token sent as a bearer token is refused. A 401 to a DPoP request
// carries the DPoP challenge, and the Authority's nonce as DPoP-Nonce.
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
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Paths of the route.
const (
	ResourcePrefix = iddomain.ResourcePath
	MetadataPrefix = "/.well-known/oauth-protected-resource" + iddomain.ResourcePath
)

// maxToken bounds a bearer token.
const maxToken = 8192

// Authorization schemes and DPoP headers (RFC 6750, RFC 9449; G0 M30 D913).
const (
	SchemeBearer    = "Bearer"
	SchemeDPoP      = "DPoP"
	HeaderDPoP      = "DPoP"
	HeaderDPoPNonce = "DPoP-Nonce"
)

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
	scheme, token, _ := strings.Cut(r.Header.Get("Authorization"), " ")
	dpop := scheme == SchemeDPoP
	if (scheme != SchemeBearer && !dpop) || token == "" || len(token) > maxToken || len(r.Header.Values("Authorization")) != 1 {
		h.challenge(w, conn, "", false)
		return
	}
	if r.Header.Get(dispatch.HeaderProof) != "" {
		// A bearer token carries no PAP/1 proof (D408).
		h.challenge(w, conn, "invalid_request", dpop)
		return
	}
	proofs := r.Header.Values(HeaderDPoP)
	if dpop && (len(proofs) != 1 || proofs[0] == "" || len(proofs[0]) > pap.MaxProofBytes) {
		// The DPoP scheme needs exactly one proof (RFC 9449 §4.3, §7.1).
		h.challenge(w, conn, "invalid_dpop_proof", true)
		return
	}
	c := claimsOf(token)
	if c.run == "" {
		// Every MCP access token names its run; one that names none is no
		// MCP access token (a workload token, say), and is not forwarded.
		h.challenge(w, conn, "invalid_token", dpop || c.bound)
		return
	}
	fwd := r.Clone(mcp.WithOAuth(r.Context(), h.resource(conn)))
	fwd.Header.Set("Authorization", "PAP "+token)
	fwd.Header.Del(dispatch.HeaderProof)
	// Only this route says a request came under the DPoP scheme: the proof
	// travels as PC-MCP-DPoP, and a client's own copy is never forwarded
	// (G0 M30 D913). Under the Bearer scheme no proof is forwarded, so the
	// Authority refuses a DPoP-bound token sent as a bearer token.
	fwd.Header.Del(dispatch.HeaderMcpDPoP)
	fwd.Header.Del(HeaderDPoP)
	if dpop {
		fwd.Header.Set(dispatch.HeaderMcpDPoP, proofs[0])
	}
	fwd.Header.Set(dispatch.HeaderRunID, c.run)
	fwd.URL.Path, fwd.URL.RawPath = "/mcp/"+conn, ""
	h.mcp.ServeHTTP(&challenger{ResponseWriter: w, h: h, conn: conn, dpop: dpop || c.bound}, fwd)
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
		// DPoP-bound tokens are accepted; standard clients keep bearer
		// tokens (G0 M30 D914, FD4).
		"dpop_signing_alg_values_supported": pap.ProofAlgorithms,
		"dpop_bound_access_tokens_required": false,
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
// URL (RFC 9728 §5.1); under the DPoP scheme, or for a DPoP-bound token,
// with the RFC 9449 §7.1 challenge. A request with no usable credentials
// gets both.
func (h *Handler) challenge(w http.ResponseWriter, conn, errCode string, dpop bool) {
	w.Header().Set("WWW-Authenticate", h.wwwAuthenticate(conn, errCode, dpop))
	if errCode == "" && !dpop {
		w.Header().Add("WWW-Authenticate", h.wwwAuthenticate(conn, "", true))
	}
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (h *Handler) wwwAuthenticate(conn, errCode string, dpop bool) string {
	v := SchemeBearer + ` resource_metadata="` + h.metadataURL(conn) + `"`
	if dpop {
		v = SchemeDPoP + ` resource_metadata="` + h.metadataURL(conn) + `", algs="` + strings.Join(pap.ProofAlgorithms, " ") + `"`
	}
	if errCode != "" {
		v += `, error="` + errCode + `"`
	}
	return v
}

// challenger adds the challenge to the MCP face's refusals: a 401 is an
// invalid token, a 403 a token whose scope does not cover the call. For a
// DPoP request (G0 M30 D913) a 401 the Authority refused for want of a
// live nonce is use_dpop_nonce, and its nonce is relayed as DPoP-Nonce.
type challenger struct {
	http.ResponseWriter
	h     *Handler
	conn  string
	dpop  bool
	wrote bool
}

func (c *challenger) WriteHeader(status int) {
	if !c.wrote {
		c.wrote = true
		switch status {
		case http.StatusUnauthorized:
			code := "invalid_token"
			if c.dpop {
				if pap.Code(c.Header().Get(dispatch.HeaderError)) == pap.CodeUseNonce {
					code = "use_dpop_nonce"
				}
				if n := c.Header().Get(dispatch.HeaderNonce); n != "" {
					c.Header().Set(HeaderDPoPNonce, n)
				}
			}
			c.Header().Set("WWW-Authenticate", c.h.wwwAuthenticate(c.conn, code, c.dpop))
		case http.StatusForbidden:
			c.Header().Set("WWW-Authenticate", c.h.wwwAuthenticate(c.conn, "insufficient_scope", c.dpop))
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

// peeked is what an MCP access token says, read WITHOUT verifying it.
type peeked struct {
	// run is the call's run, which the Authority checks is the token's.
	run string
	// bound: the token names a DPoP key, so a refusal is a DPoP challenge;
	// the Authority alone decides whether it is bound (G0 M30 D913).
	bound bool
}

// claimsOf reads, WITHOUT verifying, the run an MCP access token names and
// whether it says it is DPoP-bound.
func claimsOf(token string) peeked {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return peeked{}
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return peeked{}
	}
	var c struct {
		Cnf *struct {
			JKT string `json:"jkt"`
		} `json:"cnf"`
		PAP struct {
			Run   string `json:"run"`
			Proof string `json:"proof"`
		} `json:"pap"`
	}
	if json.Unmarshal(payload, &c) != nil {
		return peeked{}
	}
	bound := c.Cnf != nil || c.PAP.Proof == "dpop"
	run, err := ids.ParseUUID(c.PAP.Run)
	if err != nil || run.IsZero() {
		return peeked{bound: bound}
	}
	return peeked{run: run.String(), bound: bound}
}
