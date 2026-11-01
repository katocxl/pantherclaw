// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	credapp "github.com/katocxl/pantherclaw/internal/credentials/app"
	creddomain "github.com/katocxl/pantherclaw/internal/credentials/domain"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/protect"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The credential rotation page (G0 M22 D5, F831; HR-518, HR-519, HR-553):
// GET /integrations/credential-rotations/{id} shows a rotation. A person
// holding credential.seal activates it or rolls it back with a POST right
// after a security-key step-up on this browser session; no API call, key or
// link does either. A held change answers 409 protected_change_pending. GET
// never changes anything; every POST carries the CSRF proof (HR-151).

// CredentialRotationsPath is the page's path.
const CredentialRotationsPath = "/integrations/credential-rotations"

// CredentialRotations is the rotation use-case set (credentials/app).
type CredentialRotations interface {
	GetRotation(ctx context.Context, rotation ids.UUID) (credapp.Rotation, error)
	ActivateRotation(ctx context.Context, rotation ids.UUID, su credapp.StepUp) (credapp.Rotation, error)
	RollBackRotation(ctx context.Context, rotation ids.UUID, reason string, su credapp.StepUp) (credapp.Rotation, error)
}

// WithCredentialRotations adds the rotation page; call it before Mount.
func (h *Handler) WithCredentialRotations(c CredentialRotations) *Handler {
	h.credentialRotations = c
	return h
}

func (h *Handler) mountCredentialRotations(m *http.ServeMux) {
	if h.credentialRotations == nil {
		return
	}
	h.withSession(m, http.MethodGet, CredentialRotationsPath+"/{id}", h.credentialRotationPage)
	h.withSession(m, http.MethodPost, CredentialRotationsPath+"/{id}/activate", h.activateCredentialRotation)
	h.withSession(m, http.MethodPost, CredentialRotationsPath+"/{id}/rollback", h.rollBackCredentialRotation)
}

// credentialRotationView is the data of integration_credential_rotation.html.
// The page offers each action in the state that allows it; the use case
// decides.
type credentialRotationView struct {
	page
	credapp.Rotation

	CanActivate, CanRollBack bool
}

func (h *Handler) credentialRotationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Credential rotation"
	id, err := ids.ParseUUID(r.PathValue("id"))
	var c credapp.Rotation
	if err == nil {
		c, err = h.credentialRotations.GetRotation(callerContext(r, s), id)
	} else {
		err = credapp.ErrRotationNotFound
	}
	switch code := pcerr.CodeOf(err); {
	case err == nil:
	case code == pcerr.NotFound || code == pcerr.PermissionDenied || code == pcerr.InvalidArgument:
		h.integrationNotFound(w, title)
		return
	default:
		h.fail(w, r, err)
		return
	}
	may := s.Human() && s.Can(protect.SurfaceCredentialRotate.Permission(), td.OrgPath(s.Org))
	h.renderAny(w, http.StatusOK, "integration_credential_rotation.html", credentialRotationView{
		page: page{Title: title, Session: s}, Rotation: c,
		CanActivate: may && c.State == string(creddomain.RotationTesting) && c.TestPassedAt != nil,
		CanRollBack: may && c.State == string(creddomain.RotationActivating),
	})
}

// credentialRotationErrors maps the use cases' errors to the page's codes.
var credentialRotationErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{protect.ErrPending, http.StatusConflict, "protected_change_pending"},
	{credapp.ErrRotationNotFound, http.StatusNotFound, "not_found"},
	{credapp.ErrRotationUntested, http.StatusConflict, "rotation_untested"},
	{credapp.ErrRotationState, http.StatusConflict, "rotation_state"},
	{credapp.ErrRollbackClosed, http.StatusConflict, "rollback_closed"},
	{credapp.ErrRotationReason, http.StatusBadRequest, "rotation_reason"},
}

func (h *Handler) rotationResult(w http.ResponseWriter, r *http.Request, c credapp.Rotation, err error) {
	if err == nil {
		h.writeJSON(w, http.StatusOK, map[string]string{"state": c.State})
		return
	}
	for _, e := range credentialRotationErrors {
		if errors.Is(err, e.err) {
			h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	h.log.ErrorContext(r.Context(), "web.credential_rotations", pclog.Err(err))
	h.jsonError(w, http.StatusInternalServerError, "internal")
}

func (h *Handler) activateCredentialRotation(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	c, err := h.credentialRotations.ActivateRotation(callerContext(r, s), id, stepUpOfSession(s))
	h.rotationResult(w, r, c, err)
}

// maxRotationBody bounds a rollback's body: a reason of at most 500
// characters, each at most four bytes, escaped at worst.
const maxRotationBody = 8 << 10

func (h *Handler) rollBackCredentialRotation(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := h.requestID(w, r)
	if !ok {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRotationBody))
	if err == nil {
		err = json.Unmarshal(b, &body, json.RejectUnknownMembers(true))
	}
	if err != nil {
		h.jsonError(w, http.StatusBadRequest, "rotation_reason")
		return
	}
	c, err := h.credentialRotations.RollBackRotation(callerContext(r, s), id, body.Reason, stepUpOfSession(s))
	h.rotationResult(w, r, c, err)
}
