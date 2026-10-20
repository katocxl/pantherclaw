// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/url"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Keys is the security-key use-case set (authn/app.WebAuthn).
type Keys interface {
	BeginRegistration(ctx context.Context, s authnapp.BrowserSession) (authnapp.Ceremony, error)
	FinishRegistration(ctx context.Context, s authnapp.BrowserSession, ceremony ids.UUID, name string, response []byte) (authnapp.CredentialInfo, error)
	BeginStepUp(ctx context.Context, s authnapp.BrowserSession) (authnapp.Ceremony, error)
	FinishStepUp(ctx context.Context, s authnapp.BrowserSession, ceremony ids.UUID, response []byte) (authnapp.StepUp, error)
	ListCredentials(ctx context.Context, s authnapp.BrowserSession) ([]authnapp.CredentialInfo, error)
	RenameCredential(ctx context.Context, s authnapp.BrowserSession, id ids.UUID, name string) error
	RemoveCredential(ctx context.Context, s authnapp.BrowserSession, id ids.UUID) error
}

// WithKeys adds the security-key routes; call it before Mount.
func (h *Handler) WithKeys(k Keys) *Handler {
	h.keys = k
	return h
}

func (h *Handler) mountKeys(m *http.ServeMux) {
	if h.keys == nil {
		return
	}
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/keys/registration-options", h.registrationOptions)
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/keys", h.addKey)
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/keys/{id}/rename", h.renameKey)
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/keys/{id}/remove", h.removeKey)
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/step-up-options", h.stepUpOptions)
	h.withSession(m, http.MethodPost, authnapp.AccountPath+"/step-up", h.stepUp)
}

// ceremonyJSON is what the page passes to navigator.credentials.
type ceremonyJSON struct {
	Ceremony string         `json:"ceremony"`
	Options  jsontext.Value `json:"options"`
}

// keyRequest is the body of the key routes; each route reads its fields.
type keyRequest struct {
	Ceremony string         `json:"ceremony,omitzero"`
	Name     string         `json:"name,omitzero"`
	Response jsontext.Value `json:"response,omitzero"`
}

// readKeyRequest decodes a strict JSON body (unknown members, duplicate
// names and invalid UTF-8 are refused).
func readKeyRequest(r *http.Request) (keyRequest, error) {
	var k keyRequest
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return k, err
	}
	err = json.Unmarshal(b, &k, json.RejectUnknownMembers(true))
	return k, err
}

// keyErrors maps use-case errors to the page's error codes.
var keyErrors = []struct {
	err    error
	status int
	code   string
}{
	{authnapp.ErrRecentAuthRequired, http.StatusForbidden, "recent_auth_required"},
	{authnapp.ErrNoCredentials, http.StatusConflict, "no_keys"},
	{authnapp.ErrCeremonyInvalid, http.StatusBadRequest, "ceremony_invalid"},
	{authnapp.ErrWebAuthnFailed, http.StatusBadRequest, "verification_failed"},
	{authnapp.ErrCredentialSuspended, http.StatusForbidden, "key_suspended"},
	{authnapp.ErrCredentialExists, http.StatusConflict, "key_exists"},
	{authnapp.ErrTooManyCredentials, http.StatusConflict, "too_many_keys"},
	{authnapp.ErrCredentialNotFound, http.StatusNotFound, "not_found"},
	{authnapp.ErrBadCredentialName, http.StatusBadRequest, "bad_name"},
}

func (h *Handler) keyError(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession, err error) {
	for _, e := range keyErrors {
		if errors.Is(err, e.err) {
			body := map[string]string{"error": e.code}
			if e.code == "recent_auth_required" {
				// The console names the page to come back to in return_to;
				// only a same-origin console path is taken (HR-345).
				next := authnapp.AccountPath
				if rt := r.URL.Query().Get("return_to"); authnapp.ValidConsolePath(rt) {
					next = rt
				}
				q := url.Values{"org": {s.Org.String()}, "next": {next}, "recent": {"1"}}
				body["sign_in"] = authnapp.LoginPath + "?" + q.Encode()
			}
			h.writeJSON(w, e.status, body)
			return
		}
	}
	h.log.ErrorContext(r.Context(), "web.keys", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) writeCeremony(w http.ResponseWriter, c authnapp.Ceremony) {
	h.writeJSON(w, http.StatusOK, ceremonyJSON{Ceremony: c.ID.String(), Options: jsontext.Value(c.Options)})
}

func (h *Handler) registrationOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	c, err := h.keys.BeginRegistration(r.Context(), s)
	if err != nil {
		h.keyError(w, r, s, err)
		return
	}
	h.writeCeremony(w, c)
}

func (h *Handler) addKey(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	req, err := readKeyRequest(r)
	id, perr := ids.ParseUUID(req.Ceremony)
	if err != nil || perr != nil || len(req.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	k, err := h.keys.FinishRegistration(r.Context(), s, id, req.Name, req.Response)
	if err != nil {
		h.keyError(w, r, s, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"id": k.ID.String(), "name": k.Name})
}

func (h *Handler) renameKey(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	req, err := readKeyRequest(r)
	id, perr := ids.ParseUUID(r.PathValue("id"))
	if err != nil || perr != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	if err := h.keys.RenameCredential(r.Context(), s, id, req.Name); err != nil {
		h.keyError(w, r, s, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"renamed": true})
}

func (h *Handler) removeKey(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		h.jsonError(w, http.StatusNotFound, "not_found")
		return
	}
	if err := h.keys.RemoveCredential(r.Context(), s, id); err != nil {
		h.keyError(w, r, s, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"removed": true})
}

func (h *Handler) stepUpOptions(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	c, err := h.keys.BeginStepUp(r.Context(), s)
	if err != nil {
		h.keyError(w, r, s, err)
		return
	}
	h.writeCeremony(w, c)
}

func (h *Handler) stepUp(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	req, err := readKeyRequest(r)
	id, perr := ids.ParseUUID(req.Ceremony)
	if err != nil || perr != nil || len(req.Response) == 0 {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	up, err := h.keys.FinishStepUp(r.Context(), s, id, req.Response)
	if err != nil {
		h.keyError(w, r, s, err)
		return
	}
	if up.Rotated != "" {
		h.setCookie(w, sessionCookie, up.Rotated, authnapp.BrowserSessionLifetime, http.SameSiteStrictMode)
	}
	h.writeJSON(w, http.StatusOK, map[string]bool{"verified": true})
}
