// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"maps"
	"net/http"
	"slices"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	autodomain "github.com/katocxl/pantherclaw/internal/automations/domain"
	"github.com/katocxl/pantherclaw/internal/automations/triggers"
	"github.com/katocxl/pantherclaw/internal/automations/triggers/endpoints"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The automation endpoint pages (G0 M11 part 2 D20–D22, D53; HR-275):
//
//	GET  /automations/sources/{id}/confirm        an inbound event source
//	POST /automations/sources/{id}/activate       activate it
//	POST /automations/sources/{id}/rotate         rotate its secret
//	GET  /automations/destinations/{id}/confirm   an automation destination
//	POST /automations/destinations/{id}/activate  activate it
//	POST /automations/destinations/{id}/rotate    rotate its secret
//	GET  /automations/{id}/start                  start an automation by hand
//	POST /automations/{id}/start                  start it
//
// Activating, rotating and a start whose version requires it need a
// security-key step-up of this browser session within five minutes, made
// right before on the page; the API refuses them (STEP_UP_REQUIRED). GET
// never changes anything; every POST carries the CSRF proof (HR-151). A
// rotated secret is shown once, in the POST's answer.

// Automation page paths.
const (
	AutomationSourcesPath      = "/automations/sources"
	AutomationDestinationsPath = "/automations/destinations"
	AutomationsPath            = "/automations"
)

// AutomationEndpoints is the use-case set of the pages (endpoints.Service
// and triggers.Service).
type AutomationEndpoints interface {
	EventSource(ctx context.Context, id ids.UUID) (endpoints.Source, error)
	ActivateEventSource(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Source, error)
	RotateEventSourceSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error)
	Destination(ctx context.Context, id ids.UUID) (endpoints.Destination, error)
	ActivateDestination(ctx context.Context, id ids.UUID, su *stepup.StepUp) (endpoints.Destination, error)
	RotateDestinationSecret(ctx context.Context, id ids.UUID, su *stepup.StepUp) (string, error)
	Form(ctx context.Context, automation ids.UUID) (triggers.ManualForm, error)
	StartExecution(ctx context.Context, in triggers.ManualStart, su *stepup.StepUp) (triggers.Outcome, error)
}

// MountAutomationEndpoints adds the automation endpoint pages to mux. The
// server calls it after Mount when automations are served.
func (h *Handler) MountAutomationEndpoints(mux *http.ServeMux, ae AutomationEndpoints) {
	if ae == nil {
		return
	}
	p := automationPages{h: h, ae: ae}
	h.withSession(mux, http.MethodGet, AutomationSourcesPath+"/{id}/confirm", p.sourcePage)
	h.withSession(mux, http.MethodPost, AutomationSourcesPath+"/{id}/activate", p.activateSource)
	h.withSession(mux, http.MethodPost, AutomationSourcesPath+"/{id}/rotate", p.rotateSource)
	h.withSession(mux, http.MethodGet, AutomationDestinationsPath+"/{id}/confirm", p.destinationPage)
	h.withSession(mux, http.MethodPost, AutomationDestinationsPath+"/{id}/activate", p.activateDestination)
	h.withSession(mux, http.MethodPost, AutomationDestinationsPath+"/{id}/rotate", p.rotateDestination)
	h.withSession(mux, http.MethodGet, AutomationsPath+"/{id}/start", p.startPage)
	h.withSession(mux, http.MethodPost, AutomationsPath+"/{id}/start", p.start)
}

type automationPages struct {
	h  *Handler
	ae AutomationEndpoints
}

// automationSourceView is the data of automation_source.html.
type automationSourceView struct {
	page
	endpoints.Source
	Endpoint  string
	CanManage bool
}

// automationDestinationView is the data of automation_destination.html.
type automationDestinationView struct {
	page
	endpoints.Destination
	CanManage bool
}

// startParam is one parameter field of the start page.
type startParam struct {
	Name     string
	Type     string
	Required bool
	Values   []string
}

// automationStartView is the data of automation_start.html.
type automationStartView struct {
	page
	ID     ids.UUID
	Name   string
	Params []startParam
	StepUp bool
}

func (p automationPages) sameOrg(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) bool {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		p.h.toLogin(w, r)
		return false
	}
	return true
}

func (p automationPages) notFound(w http.ResponseWriter, title string) {
	p.h.render(w, http.StatusNotFound, "error.html", page{
		Title: title, Message: "This does not exist, or you cannot see it.",
	})
}

// pageError renders a GET's failure.
func (p automationPages) pageError(w http.ResponseWriter, r *http.Request, title string, err error) {
	switch pcerr.CodeOf(err) { //nolint:exhaustive // these read as "not found"; the rest fail
	case pcerr.NotFound, pcerr.PermissionDenied, pcerr.InvalidArgument, pcerr.FailedPrecondition:
		p.notFound(w, title)
	default:
		p.h.fail(w, r, err)
	}
}

func (p automationPages) canManage(s authnapp.BrowserSession) bool {
	return s.Human() && s.Can(td.PermAutomationEndpointsManage, td.OrgPath(s.Org))
}

func (p automationPages) sourcePage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if !p.sameOrg(w, r, s) {
		return
	}
	const title = "Inbound event source"
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	src, err := p.ae.EventSource(callerContext(r, s), id)
	if err != nil {
		p.pageError(w, r, title, err)
		return
	}
	p.h.renderAny(w, http.StatusOK, "automation_source.html", automationSourceView{
		page: page{Title: title, Session: s}, Source: src, CanManage: p.canManage(s),
		Endpoint: p.h.origin + "/v1/automations/events/" + s.Org.String() + "/" + src.ID.String(),
	})
}

func (p automationPages) destinationPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if !p.sameOrg(w, r, s) {
		return
	}
	const title = "Automation destination"
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	d, err := p.ae.Destination(callerContext(r, s), id)
	if err != nil {
		p.pageError(w, r, title, err)
		return
	}
	p.h.renderAny(w, http.StatusOK, "automation_destination.html", automationDestinationView{
		page: page{Title: title, Session: s}, Destination: d, CanManage: p.canManage(s),
	})
}

func (p automationPages) startPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if !p.sameOrg(w, r, s) {
		return
	}
	const title = "Start an automation"
	id, err := ids.ParseUUID(r.PathValue("id"))
	if err != nil {
		p.notFound(w, title)
		return
	}
	f, err := p.ae.Form(callerContext(r, s), id)
	if err != nil {
		p.pageError(w, r, title, err)
		return
	}
	v := automationStartView{page: page{Title: title, Session: s}, ID: f.Automation, Name: f.Name, StepUp: f.StepUp}
	for _, name := range slices.Sorted(maps.Keys(f.Params)) {
		spec := f.Params[name]
		v.Params = append(v.Params, startParam{Name: name, Type: string(spec.Type), Required: spec.IsRequired(), Values: spec.Values})
	}
	p.h.renderAny(w, http.StatusOK, "automation_start.html", v)
}

// automationErrors maps the use cases' errors to the pages' codes.
var automationErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{endpoints.ErrNotFound, http.StatusNotFound, "not_found"},
	{triggers.ErrNotFound, http.StatusNotFound, "not_found"},
	{endpoints.ErrState, http.StatusConflict, "not_pending"},
	{endpoints.ErrRotating, http.StatusConflict, "rotating"},
	{endpoints.ErrURL, http.StatusConflict, "url_refused"},
	{endpoints.ErrMetadata, http.StatusConflict, "url_refused"},
	{triggers.ErrHuman, http.StatusForbidden, "forbidden"},
	{triggers.ErrEdition, http.StatusForbidden, "edition"},
	{triggers.ErrNotManual, http.StatusConflict, "not_manual"},
	{triggers.ErrIdemKey, http.StatusBadRequest, "invalid"},
}

func (p automationPages) fail(w http.ResponseWriter, r *http.Request, err error) {
	for _, e := range automationErrors {
		if errors.Is(err, e.err) {
			p.h.jsonError(w, e.status, e.code)
			return
		}
	}
	if pcerr.CodeOf(err) == pcerr.PermissionDenied {
		p.h.jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	p.h.log.ErrorContext(r.Context(), "web.automation_endpoints", pclog.Err(err))
	p.h.jsonError(w, http.StatusInternalServerError, "internal")
}

// stepUpPtr is the session's step-up, nil when it never stepped up (a start
// that needs none then runs as a plain session start).
func stepUpPtr(s authnapp.BrowserSession) *stepup.StepUp {
	if s.StepUpCredential.IsZero() {
		return nil
	}
	su := stepUpOfSession(s)
	return &su
}

func (p automationPages) activateSource(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	src, err := p.ae.ActivateEventSource(callerContext(r, s), id, stepUpPtr(s))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": src.State})
}

func (p automationPages) rotateSource(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	secret, err := p.ae.RotateEventSourceSecret(callerContext(r, s), id, stepUpPtr(s))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"signing_secret": secret})
}

func (p automationPages) activateDestination(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	d, err := p.ae.ActivateDestination(callerContext(r, s), id, stepUpPtr(s))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"state": d.State})
}

func (p automationPages) rotateDestination(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	secret, err := p.ae.RotateDestinationSecret(callerContext(r, s), id, stepUpPtr(s))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{"signing_secret": secret})
}

// startBody is the start page's request.
type startBody struct {
	Params         map[string]string `json:"params,omitzero"`
	IdempotencyKey string            `json:"idempotency_key"`
}

func (p automationPages) start(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	id, ok := p.h.requestID(w, r)
	if !ok {
		return
	}
	var body startBody
	b, err := io.ReadAll(r.Body)
	if err == nil && len(bytes.TrimSpace(b)) > 0 {
		err = json.Unmarshal(b, &body, json.RejectUnknownMembers(true))
	}
	if err != nil || len(body.Params) > autodomain.MaxParams {
		p.h.jsonError(w, http.StatusBadRequest, "invalid")
		return
	}
	out, err := p.ae.StartExecution(callerContext(r, s), triggers.ManualStart{
		Automation: id, Params: body.Params, IdempotencyKey: body.IdempotencyKey,
	}, stepUpPtr(s))
	if err != nil {
		p.fail(w, r, err)
		return
	}
	p.h.writeJSON(w, http.StatusOK, map[string]string{
		"trigger": out.Trigger.String(), "state": string(out.State), "reason": out.Reason, "execution": execText(out.Execution),
	})
}

func execText(id ids.UUID) string {
	if id.IsZero() {
		return ""
	}
	return id.String()
}
