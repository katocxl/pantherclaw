// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"errors"
	"net/http"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/connections/pgmanifest"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The postgres manifest confirm page (G0 M14 D84, D92):
//
//	GET  /connections/{id}/postgres/confirm   the current and proposed configuration
//	POST /connections/{id}/postgres/confirm   confirm the proposal the page showed (?digest=)
//
// Confirming a postgres connection's first configuration, or a widening
// change of it, needs a person with connection.manage and a security-key
// step-up of this browser session within five minutes, made right before
// on the page. GET never changes anything; the POST carries the CSRF proof
// (HR-151).

// PostgresManifests is the use-case set of the page (pgmanifest.Service).
type PostgresManifests interface {
	Get(ctx context.Context, id ids.UUID) (pgmanifest.Manifest, error)
	Confirm(ctx context.Context, id ids.UUID, digest string, su *stepup.StepUp) error
}

// MountPostgresManifests adds the confirm page to mux. The server calls it
// after Mount.
func (h *Handler) MountPostgresManifests(mux *http.ServeMux, pm PostgresManifests) {
	if pm == nil {
		return
	}
	p := manifestPages{h: h, pm: pm}
	h.withSession(mux, http.MethodGet, "/connections/{id}/postgres/confirm", p.page)
	h.withSession(mux, http.MethodPost, "/connections/{id}/postgres/confirm", p.confirm)
}

type manifestPages struct {
	h  *Handler
	pm PostgresManifests
}

// postgresManifestView is the data of postgres_manifest.html.
type postgresManifestView struct {
	page
	pgmanifest.Manifest
	CanConfirm bool
}

func (p manifestPages) page(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	const title = "Postgres connection"
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return
	}
	notFound := func() {
		p.h.render(w, http.StatusNotFound, "error.html", page{Title: title, Message: "This does not exist, or you cannot see it."})
	}
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		notFound()
		return
	}
	m, err := p.pm.Get(callerContext(r, s), id)
	switch pcerr.CodeOf(err) { //nolint:exhaustive // these read as "not found"; the rest fail
	case "":
		p.h.renderAny(w, http.StatusOK, "postgres_manifest.html", postgresManifestView{
			page: page{Title: title, Session: s}, Manifest: m,
			CanConfirm: s.Human() && s.Can(td.PermConnectionManage, td.OrgPath(s.Org)),
		})
	case pcerr.NotFound, pcerr.PermissionDenied, pcerr.InvalidArgument:
		notFound()
	default:
		p.h.fail(w, r, err)
	}
}

// manifestErrors maps the use cases' errors to the page's codes.
var manifestErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{pgmanifest.ErrHuman, http.StatusForbidden, "forbidden"},
	{pgmanifest.ErrNotFound, http.StatusNotFound, "not_found"},
	{pgmanifest.ErrNothing, http.StatusConflict, "not_pending"},
	{pgmanifest.ErrChanged, http.StatusConflict, "not_pending"},
}

func (p manifestPages) confirm(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	err := p.pm.Confirm(callerContext(r, s), id, r.URL.Query().Get("digest"), stepUpPtr(s)) //nolint:contextcheck // callerContext derives from the request's context
	if err != nil {
		for _, e := range manifestErrors {
			if errors.Is(err, e.err) {
				p.h.jsonError(w, e.status, e.code)
				return
			}
		}
		if pcerr.CodeOf(err) == pcerr.PermissionDenied {
			p.h.jsonError(w, http.StatusForbidden, "forbidden")
			return
		}
		p.h.log.ErrorContext(r.Context(), "web.postgres_manifests", pclog.Err(err))
		p.h.jsonError(w, http.StatusInternalServerError, "internal")
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": "CONFIRMED"})
}
