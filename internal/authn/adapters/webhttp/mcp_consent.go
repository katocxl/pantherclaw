// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	idapp "github.com/katocxl/pantherclaw/internal/idaccess/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
)

// The MCP consent page, the org's authorization endpoint (G0 M26 D408.4,
// HR-628):
//
//	GET  /orgs/{org}/mcp/authorize   what the client asks for, and the choice
//	POST /orgs/{org}/mcp/authorize   the person's answer, as JSON
//
// It needs a person's own browser session in that org: never a support
// session. The page states the client by its URL and host (its name is the
// client's own and shown as such), the agent it acts as and the server it
// asks for, and says that consenting creates no access: the client can only
// use grants the person already gave that agent. GET never changes
// anything; the POST carries the CSRF proof (HR-151) and answers with the
// URL to send the browser to.

// McpConsent is the use-case set of the page (idaccess/app.CodeFlow).
type McpConsent interface {
	Prepare(ctx context.Context, org ids.OrgID, q url.Values) (idapp.Consent, error)
	Approve(ctx context.Context, org ids.OrgID, user ids.UUID, q url.Values) (string, error)
	Deny(ctx context.Context, org ids.OrgID, q url.Values) (string, error)
	ErrorRedirect(org ids.OrgID, r idapp.AuthorizeRequest, e *idapp.AuthorizeError) string
}

// WithMcpConsent adds the consent page; Mount mounts it.
func (h *Handler) WithMcpConsent(c McpConsent) *Handler {
	h.mcpConsent = c
	return h
}

// mcpConsentPath is the page's route pattern.
const mcpConsentPath = "/orgs/{org}/mcp/authorize"

func (h *Handler) mountMcpConsent(mux *http.ServeMux) {
	if h.mcpConsent == nil {
		return
	}
	h.withSession(mux, http.MethodGet, mcpConsentPath, h.mcpConsentPage)
	h.withSession(mux, http.MethodPost, mcpConsentPath, h.mcpConsentAnswer)
}

// mcpConsentView is the data of mcp_consent.html.
type mcpConsentView struct {
	page
	idapp.Consent
	// Query is the authorization request, posted back with the answer.
	Query string
	Path  string
}

// consentOrg is the org of the path when the session is a person's own in
// that org.
func consentOrg(r *http.Request, s authnapp.BrowserSession) (ids.OrgID, bool) {
	org, err := ids.Parse[ids.Org](r.PathValue("org"))
	if err != nil || org != s.Org || !s.Human() || s.Credential == tenancy.CredSupportSession {
		return ids.OrgID{}, false
	}
	return org, true
}

func (h *Handler) mcpConsentPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Allow an MCP client"
	org, ok := consentOrg(r, s)
	if !ok {
		h.render(w, http.StatusForbidden, "error.html", page{
			Title: title, Message: "Sign in to this organization yourself to answer this request.",
		})
		return
	}
	q := r.URL.Query()
	c, err := h.mcpConsent.Prepare(r.Context(), org, q)
	var ae *idapp.AuthorizeError
	switch {
	case errors.As(err, &ae) && ae.Redirect:
		req, _ := idapp.ParseAuthorize(q)
		// A redirected error comes only after the client and its exact
		// redirect URI were checked against its document (HR-628).
		http.Redirect(w, r, h.mcpConsent.ErrorRedirect(org, req, ae), http.StatusSeeOther) //nolint:gosec // G710: the redirect URI matched the allow-listed client's document exactly
	case errors.As(err, &ae):
		h.render(w, http.StatusBadRequest, "error.html", page{Title: title, Message: "This request can't be answered: " + ae.Description + "."})
	case err != nil:
		h.fail(w, r, err)
	default:
		h.renderAny(w, http.StatusOK, "mcp_consent.html", mcpConsentView{
			page: page{Title: title, Session: s}, Consent: c, Query: r.URL.RawQuery, Path: "/orgs/" + org.String() + "/mcp/authorize",
		})
	}
}

type mcpConsentBody struct {
	Query   string `json:"query"`
	Approve bool   `json:"approve"`
}

func (h *Handler) mcpConsentAnswer(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	org, ok := consentOrg(r, s)
	if !ok {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	var in mcpConsentBody
	if err := json.Unmarshal(b, &in, json.RejectUnknownMembers(true)); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	q, err := url.ParseQuery(in.Query)
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	var next string
	if in.Approve {
		next, err = h.mcpConsent.Approve(r.Context(), org, s.User(), q)
	} else {
		next, err = h.mcpConsent.Deny(r.Context(), org, q)
	}
	var ae *idapp.AuthorizeError
	switch {
	case errors.As(err, &ae) && ae.Redirect:
		req, _ := idapp.ParseAuthorize(q)
		h.writeJSON(w, http.StatusOK, map[string]string{"next": h.mcpConsent.ErrorRedirect(org, req, ae)})
	case errors.As(err, &ae):
		h.jsonError(w, http.StatusBadRequest, "invalid")
	case err != nil:
		h.log.ErrorContext(r.Context(), "web.mcp_consent", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
	default:
		h.writeJSON(w, http.StatusOK, map[string]string{"next": next})
	}
}
