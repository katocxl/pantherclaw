// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"strings"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/changes"
	"github.com/katocxl/pantherclaw/internal/exports"
	"github.com/katocxl/pantherclaw/internal/idps"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/sigv4"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The secret pages (G0 M22 D57): where a person types a secret, so that it
// passes through the core's own page and no console code.
//
//	GET  /integrations/export-destinations/new               the new destination form
//	POST /integrations/export-destinations/new               create it
//	GET  /integrations/export-destinations/{id}/credential   the replacement form
//	POST /integrations/export-destinations/{id}/credential   replace the credential
//	GET  /integrations/identity-providers/new                the new provider form
//	POST /integrations/identity-providers/new                create it
//
// As on the activation pages, a POST needs the permission, a person, a
// security-key step-up of this browser session within five minutes and the
// CSRF proof (HR-151); the use cases audit. GET never changes anything, and
// no response or log holds a secret.

// IdentityProvidersPath is the provider pages' path.
const IdentityProvidersPath = "/integrations/identity-providers"

// ExportSecrets is the export destination use-case set (exports.Service).
type ExportSecrets interface {
	CreateOnPage(ctx context.Context, in exports.NewDestination, su stepup.StepUp) (exports.Destination, error)
	ReplaceCredentialOnPage(ctx context.Context, id ids.UUID, c exports.Credential, su stepup.StepUp) (exports.Destination, error)
}

// IdentityProviderSecrets is the provider use-case set (idps.Service).
type IdentityProviderSecrets interface {
	CreateOnPage(ctx context.Context, in idps.Input, su stepup.StepUp) (idps.Provider, idps.Filed, error)
}

// WithExportSecrets adds the export secret pages; call it before Mount.
func (h *Handler) WithExportSecrets(e ExportSecrets) *Handler {
	h.exportSecrets = e
	return h
}

// WithIdentityProviderSecrets adds the provider page; call it before Mount.
func (h *Handler) WithIdentityProviderSecrets(i IdentityProviderSecrets) *Handler {
	h.providerSecrets = i
	return h
}

func (h *Handler) mountSecretPages(m *http.ServeMux) {
	if h.exportSecrets != nil {
		h.withSession(m, http.MethodGet, ExportDestinationsPath+"/new", h.newExportDestinationPage)
		h.withSession(m, http.MethodPost, ExportDestinationsPath+"/new", h.createExportDestination)
		h.withSession(m, http.MethodGet, ExportDestinationsPath+"/{id}/credential", h.exportCredentialPage)
		h.withSession(m, http.MethodPost, ExportDestinationsPath+"/{id}/credential", h.replaceExportCredential)
	}
	if h.providerSecrets != nil {
		h.withSession(m, http.MethodGet, IdentityProvidersPath+"/new", h.newIdentityProviderPage)
		h.withSession(m, http.MethodPost, IdentityProvidersPath+"/new", h.createIdentityProvider)
	}
}

// mayManage is the page's own refusal, before the step-up.
func mayManage(s authnapp.BrowserSession, perm td.Permission) bool {
	return s.Human() && s.Can(perm, td.OrgPath(s.Org))
}

// secretFormView is the data of the secret forms.
type secretFormView struct {
	page
	CanManage bool
	// Disabled is a destination whose credential cannot be replaced.
	Disabled    bool
	DataClasses []string
	// ID and Name are the destination whose credential is replaced.
	ID, Name, Kind string
}

func (h *Handler) secretForm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession, view secretFormView, template string) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	view.Session = s
	h.renderAny(w, http.StatusOK, template, view)
}

func (h *Handler) newExportDestinationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	h.secretForm(w, r, s, secretFormView{
		page: page{Title: "New export destination"}, CanManage: mayManage(s, exports.PermManage), DataClasses: exports.DataClasses(),
	}, "integration_export_destination_new.html")
}

func (h *Handler) exportCredentialPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Replace export credential"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var d exports.Destination
	if err == nil && h.exportDestinations != nil {
		d, err = h.exportDestinations.Get(callerContext(r, s), id)
	} else {
		err = exports.ErrNotFound
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied || c == pcerr.InvalidArgument:
		h.integrationNotFound(w, title)
		return
	default:
		h.fail(w, r, err)
		return
	}
	h.secretForm(w, r, s, secretFormView{
		page: page{Title: title}, CanManage: mayManage(s, exports.PermManage), Disabled: d.State == exports.StateDisabled, ID: d.ID.String(), Name: d.Name, Kind: d.Kind,
	}, "integration_export_credential.html")
}

func (h *Handler) newIdentityProviderPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	h.secretForm(w, r, s, secretFormView{
		page: page{Title: "New identity provider"}, CanManage: mayManage(s, td.PermIdentityProviderManage),
	}, "integration_identity_provider_new.html")
}

// maxSecretBody bounds a form's body; every field has a smaller limit of its
// own in the use case.
const maxSecretBody = 64 << 10

// secretBody decodes a form's strict JSON body. A refusal never echoes it.
func secretBody(w http.ResponseWriter, r *http.Request, into any) error {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSecretBody))
	if err != nil {
		return err
	}
	defer clear(b)
	return json.Unmarshal(b, into, json.RejectUnknownMembers(true))
}

// secretError answers a refused form with the use case's reason.
func (h *Handler) secretError(w http.ResponseWriter, r *http.Request, err error) {
	switch code := pcerr.CodeOf(err); {
	case errors.Is(err, stepup.ErrStepUp):
		h.jsonError(w, http.StatusForbidden, "step_up_required")
	case code == pcerr.PermissionDenied && pcerr.ReasonOf(err) != "EDITION_REQUIRED":
		h.jsonError(w, http.StatusForbidden, "forbidden")
	case code == pcerr.PermissionDenied:
		h.jsonError(w, http.StatusForbidden, "edition_required")
	case code == pcerr.NotFound:
		h.jsonError(w, http.StatusNotFound, "not_found")
	case code == pcerr.InvalidArgument:
		h.jsonError(w, http.StatusBadRequest, strings.ToLower(pcerr.ReasonOf(err)))
	case code == pcerr.AlreadyExists || code == pcerr.FailedPrecondition || code == pcerr.ResourceExhausted:
		h.jsonError(w, http.StatusConflict, strings.ToLower(pcerr.ReasonOf(err)))
	default:
		h.log.ErrorContext(r.Context(), "web.secret_pages", pclog.Err(err))
		h.jsonError(w, http.StatusInternalServerError, "internal")
	}
}

// exportCredentialForm is an export credential as the forms send it.
type exportCredentialForm struct {
	BearerToken     string `json:"bearer_token"`
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
}

func (f exportCredentialForm) credential() exports.Credential {
	return exports.Credential{BearerToken: f.BearerToken, S3: sigv4.Credentials{AccessKeyID: f.AccessKeyID, SecretAccessKey: f.SecretAccessKey}}
}

// confirmPath is where a destination's activation goes on.
func confirmPath(id ids.UUID) string {
	return ExportDestinationsPath + "/" + id.String() + "/confirm"
}

func (h *Handler) createExportDestination(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if !mayManage(s, exports.PermManage) {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var f struct {
		exportCredentialForm

		Name        string   `json:"name"`
		Kind        string   `json:"kind"`
		URL         string   `json:"url"`
		Bucket      string   `json:"bucket"`
		Region      string   `json:"region"`
		KeyPrefix   string   `json:"key_prefix"`
		PathStyle   bool     `json:"path_style"`
		Internal    bool     `json:"internal"`
		DataClasses []string `json:"data_classes"`
	}
	if err := secretBody(w, r, &f); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, err := h.exportSecrets.CreateOnPage(callerContext(r, s), exports.NewDestination{
		Name: f.Name, DataClasses: f.DataClasses, Credential: f.credential(),
		Target: exports.Target{
			Kind: f.Kind, URL: f.URL, Bucket: f.Bucket, Region: f.Region, KeyPrefix: f.KeyPrefix, PathStyle: f.PathStyle, Internal: f.Internal,
		},
	}, stepUpOfSession(s))
	if err != nil {
		h.secretError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{"id": d.ID.String(), "state": d.State, "next": confirmPath(d.ID)})
}

func (h *Handler) replaceExportCredential(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	if !mayManage(s, exports.PermManage) {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var f exportCredentialForm
	if err := secretBody(w, r, &f); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	d, err := h.exportSecrets.ReplaceCredentialOnPage(callerContext(r, s), id, f.credential(), stepUpOfSession(s))
	if err != nil {
		h.secretError(w, r, err)
		return
	}
	out := map[string]string{"id": d.ID.String(), "state": d.State}
	if d.State == exports.StatePending {
		out["next"] = confirmPath(d.ID)
	}
	h.writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createIdentityProvider(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if !mayManage(s, td.PermIdentityProviderManage) {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	var f struct {
		Name         string `json:"name"`
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		TrustEmail   bool   `json:"trust_email"`
	}
	if err := secretBody(w, r, &f); err != nil {
		h.jsonError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	in := idps.Input{Name: f.Name, Issuer: f.Issuer, ClientID: f.ClientID, TrustEmail: f.TrustEmail}
	if f.ClientSecret != "" {
		in.ClientSecret = pclog.NewSecret([]byte(f.ClientSecret))
	}
	p, filed, err := h.providerSecrets.CreateOnPage(callerContext(r, s), in, stepUpOfSession(s))
	if err != nil {
		h.secretError(w, r, err)
		return
	}
	h.writeJSON(w, http.StatusOK, map[string]string{
		"id": p.ID.String(), "state": p.State, "change": filed.Change.String(), "request": filed.Request.String(),
		"change_path": changes.Path + "/" + filed.Request.String(),
	})
}
