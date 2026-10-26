// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package datarequests

import (
	"encoding/json/v2"
	"html/template"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/authn/adapters/webhttp"
	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

var confirmation = template.Must(template.New("data").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><link rel="stylesheet" href="/static/pc.css"></head><body><main><h1>{{.Title}}</h1><p>Organisation: <code>{{.Org}}</code>.</p><p>{{.Description}}</p><p><button type="button" data-action="confirm" data-path="{{.Path}}">Confirm with your security key</button></p><p id="status" role="status"></p><p><a href="/app/settings/data">Return to data settings</a></p><script src="/static/automation_endpoints.js"></script></main></body></html>`))

// MountPages uses the standard session, headers, rate limit and CSRF
// middleware. GET only displays the exact org and action; POST rechecks
// the DB session's live security-key step-up before any mutation.
func MountPages(mux *http.ServeMux, h *webhttp.Handler, s *Service) {
	type route struct {
		path, title, description string
		permission               td.Permission
		deletion                 bool
	}
	for _, rt := range []route{
		{"/data/export", "Export organisation data", "Create a signed export of the reviewed configuration and full evidence proofs. Secret material, captures and raw evaluation inputs are excluded. Download it from data settings within seven days.", td.PermDataExport, false},
		{"/data/delete", "Delete organisation", "Request permanent deletion after seven days. Any organisation administrator can cancel during that window. An active organisation legal hold blocks deletion. A signed deletion record remains; retained backups expire on their configured schedule.", td.PermOrgDelete, true},
	} {
		h.SessionRoute(mux, "GET "+rt.path, false, func(w http.ResponseWriter, r *http.Request, session authnapp.BrowserSession) {
			ctx := tapp.WithCaller(r.Context(), session.Caller)
			if org := r.URL.Query().Get("org"); org != "" && org != session.Org.String() {
				h.JSONError(w, http.StatusForbidden, "wrong_organisation")
				return
			}
			if _, err := human(ctx, rt.permission); err != nil || rt.deletion && session.Org == ids.PlatformOrg {
				h.JSONError(w, http.StatusForbidden, "forbidden")
				return
			}
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = confirmation.Execute(w, struct{ Title, Org, Description, Path string }{rt.title, session.Org.String(), rt.description, rt.path + "?org=" + session.Org.String()})
		})
		h.SessionRoute(mux, "POST "+rt.path, true, func(w http.ResponseWriter, r *http.Request, session authnapp.BrowserSession) {
			if r.URL.Query().Get("org") != session.Org.String() {
				h.JSONError(w, http.StatusForbidden, "wrong_organisation")
				return
			}
			ctx := audit.WithAuthKind(tapp.WithCaller(r.Context(), session.Caller), "browser_session")
			var out dbq.PcDataRequest
			var err error
			if rt.deletion {
				out, err = s.RequestDeletionPage(ctx)
			} else {
				out, err = s.CreateExportPage(ctx)
			}
			if err != nil {
				status := http.StatusConflict
				switch pcerr.CodeOf(err) {
				case pcerr.PermissionDenied:
					status = http.StatusForbidden
				case pcerr.Unauthenticated:
					status = http.StatusUnauthorized
				case pcerr.Internal:
					status = http.StatusInternalServerError
				}
				if status == http.StatusInternalServerError {
					h.InternalError(w, r, err)
					return
				}
				h.JSONError(w, status, pcerr.ReasonOf(err))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			raw, err := json.Marshal(map[string]string{"id": out.ID.String(), "state": out.State})
			if err != nil {
				h.InternalError(w, r, err)
				return
			}
			_, _ = w.Write(raw)
		})
	}
}
