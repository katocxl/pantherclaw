// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package webhttp

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"slices"

	authnapp "github.com/katocxl/pantherclaw/internal/authn/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/promotions"
	"github.com/katocxl/pantherclaw/internal/siem/stepup"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The promotions page (G0 M11 part 2, D39, D53; HR-290): GET
// /agents/{id}/promote?environment=ID[&operation=OP…] shows each
// operation's readiness for production, check by check; a person holding
// agent.promote promotes the ready operations with a POST on the same path
// right after a security-key step-up on this browser session. A step-up
// exists only on a browser session, so this page is the only way to
// promote: the API refuses STEP_UP_REQUIRED. GET never changes anything;
// every POST carries the CSRF proof (HR-151).

// PromotionsPath prefixes the promotions page: PromotionsPath/{id}/promote.
const PromotionsPath = "/agents"

// Promotions is the promotion use-case set (promotions.Service).
type Promotions interface {
	GetReadiness(ctx context.Context, agent, env ids.UUID, operations []string, failureBehavior string) ([]promotions.Readiness, error)
	PromoteAgent(ctx context.Context, in promotions.PromoteInput, su *stepup.StepUp) (promotions.Result, error)
}

// WithPromotions adds the promotions page; call it before Mount.
func (h *Handler) WithPromotions(p Promotions) *Handler {
	h.promotions = p
	return h
}

func (h *Handler) mountPromotions(m *http.ServeMux) {
	if h.promotions == nil {
		return
	}
	h.withSession(m, http.MethodGet, PromotionsPath+"/{id}/promote", h.promotionsPage)
	h.withSession(m, http.MethodPost, PromotionsPath+"/{id}/promote", h.promote)
}

// promotionsView is the data of promotions.html.
type promotionsView struct {
	page
	Agent, Environment string
	Readiness          []promotions.Readiness
	FailureBehaviors   []string
	CanPromote         bool
}

func (h *Handler) promotionsPage(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	if org := r.URL.Query().Get("org"); org != "" && org != s.Org.String() {
		h.toLogin(w, r)
		return
	}
	const title = "Production promotion"
	agent, err := ids.ParseUUID(r.PathValue("id"))
	var env ids.UUID
	if err == nil {
		env, err = ids.ParseUUID(r.URL.Query().Get("environment"))
	}
	if err != nil {
		err = promotions.ErrAgentNotFound // a malformed id is "not found"
	}
	var rs []promotions.Readiness
	if err == nil {
		rs, err = h.promotions.GetReadiness(callerContext(r, s), agent, env, r.URL.Query()["operation"], "")
	}
	switch c := pcerr.CodeOf(err); {
	case err == nil:
	case c == pcerr.NotFound || c == pcerr.PermissionDenied || c == pcerr.InvalidArgument || c == pcerr.FailedPrecondition:
		h.render(w, http.StatusNotFound, "error.html", page{
			Title: title, Message: "This agent does not exist in that environment, or you cannot see it.",
		})
		return
	default:
		h.fail(w, r, err)
		return
	}
	h.renderAny(w, http.StatusOK, "promotions.html", promotionsView{
		page: page{Title: title, Session: s}, Agent: agent.String(), Environment: env.String(), Readiness: rs,
		FailureBehaviors: promotions.FailureBehaviors,
		CanPromote:       s.Human() && s.CanAnywhere(td.PermAgentPromote),
	})
}

// promoteRequest is the POST body.
type promoteRequest struct {
	Environment     string   `json:"environment_id"`
	Operations      []string `json:"operations"`
	FailureBehavior string   `json:"failure_behavior"`
}

// promotionErrors maps the use case's errors to the page's codes.
var promotionErrors = []struct {
	err    error
	status int
	code   string
}{
	{stepup.ErrStepUp, http.StatusForbidden, "step_up_required"},
	{promotions.ErrAgentNotFound, http.StatusNotFound, "not_found"},
	{promotions.ErrEnvironment, http.StatusConflict, "environment_mismatch"},
	{promotions.ErrNotProduction, http.StatusConflict, "not_production"},
	{promotions.ErrHumanOnly, http.StatusForbidden, "forbidden"},
	{promotions.ErrCompromised, http.StatusForbidden, "forbidden"},
}

func (h *Handler) promote(w http.ResponseWriter, r *http.Request, s authnapp.BrowserSession) {
	agent, ok := h.requestID(w, r)
	if !ok {
		return
	}
	var req promoteRequest
	if b, err := io.ReadAll(r.Body); err != nil || json.Unmarshal(b, &req, json.RejectUnknownMembers(true)) != nil {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	env, err := ids.ParseUUID(req.Environment)
	if err != nil || len(req.Operations) == 0 || !slices.Contains(promotions.FailureBehaviors, req.FailureBehavior) {
		h.jsonError(w, http.StatusBadRequest, "bad_request")
		return
	}
	ctx, su := callerContext(r, s), stepUpOfSession(s)
	res, err := h.promotions.PromoteAgent(ctx, promotions.PromoteInput{
		Agent: agent, Environment: env, Operations: req.Operations, FailureBehavior: req.FailureBehavior,
	}, &su)
	if err != nil {
		for _, e := range promotionErrors {
			if errors.Is(err, e.err) {
				h.jsonError(w, e.status, e.code)
				return
			}
		}
		if c := pcerr.CodeOf(err); c == pcerr.PermissionDenied {
			h.jsonError(w, http.StatusForbidden, "forbidden")
		} else if c == pcerr.InvalidArgument {
			h.jsonError(w, http.StatusBadRequest, "bad_request")
		} else {
			h.log.ErrorContext(ctx, "web.promotions", pclog.Err(err))
			h.jsonError(w, http.StatusInternalServerError, "internal")
		}
		return
	}
	out := map[string][]string{"promoted": {}, "already": {}, "not_ready": {}}
	for _, p := range res.Promoted {
		out["promoted"] = append(out["promoted"], p.Operation)
	}
	for _, p := range res.Already {
		out["already"] = append(out["already"], p.Operation)
	}
	for _, rd := range res.Readiness {
		if rd.Promotion == nil {
			out["not_ready"] = append(out["not_ready"], rd.Operation)
		}
	}
	h.writeJSON(w, http.StatusOK, out)
}
