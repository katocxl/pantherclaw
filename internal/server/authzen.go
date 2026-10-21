// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"container/list"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/katocxl/pantherclaw/internal/authority"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/clock"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/ratelimit"
	tapp "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The AuthZEN decision endpoint (G0 M14 D26-D28; PN-023, ADR-0019; the
// AuthZEN Authorization API 1.0), on the server's public listener outside
// Connect:
//
//	GET  /.well-known/authzen-configuration  the PDP metadata (no credential)
//	POST /access/v1/evaluation               one decision
//	POST /access/v1/evaluations              up to 10 decisions
//
// The caller is a registered enforcement point: a bearer access token of
// its service account, which holds authzen.evaluate and is the subject of
// an ACTIVE point (401 otherwise), naming only connections bound to that
// point (403 otherwise; HR-317). The subject of every decision is the
// agent itself, its PAP/1 token and proof over the request the point is
// about to forward, verified exactly as the gateway's are (HR-318); a
// subject that only names someone is refused. A denial is 200 with
// decision false. Bodies are at most 128 KiB, a forwarded body 64 KiB, and
// each point has its own rate a second (HR-321), counted in the shared
// limiter across every instance; a counter error refuses (HR-376).
const (
	authzenConfigPath      = "/.well-known/authzen-configuration"
	authzenEvaluationPath  = "/access/v1/evaluation"
	authzenEvaluationsPath = "/access/v1/evaluations"
	// AuthZENCapability names PantherClaw's PAP/1 subject profile.
	AuthZENCapability = "urn:pantherclaw:authzen:pap1-subject"
	authzenMaxBody    = 128 << 10
	authzenMaxBatch   = 10
)

// Refusals of a whole request.
const (
	authzenUnauthorized = "unauthorized"
	authzenForbidden    = "connection_not_bound"
	authzenRateLimited  = "rate_limited"
	authzenTooLarge     = "too_large"
	authzenInvalid      = "invalid_request"
	authzenMediaType    = "unsupported_media_type"
	authzenUnavailable  = "try_again_later"
)

// authzenAuthenticator turns a bearer credential into a caller.
type authzenAuthenticator interface {
	Authenticate(ctx context.Context, bearer string) (tapp.Caller, error)
}

// authzenDecider decides an enforcement point's action, or verifies the
// credentials of a request that decides nothing (authority.Service).
type authzenDecider interface {
	Decide(ctx context.Context, req authority.ExternalRequest) (authority.ExternalResult, error)
	Verify(ctx context.Context, gw authority.Gateway, c *authority.Credentials, run ids.UUID) (authority.Verified, error)
}

// authzenEndpoint serves the decision endpoint.
type authzenEndpoint struct {
	pool      *db.Pool
	authn     authzenAuthenticator
	decider   authzenDecider
	publicURL string
	mappers   *mapperCache
	rates     pointLimiter
	// pointOf finds the caller's ACTIVE point (activePoint; tests replace it).
	pointOf func(ctx context.Context, c tapp.Caller) (point, error)
	log     *slog.Logger
}

func newAuthZENEndpoint(pool *db.Pool, authn authzenAuthenticator, decider authzenDecider, publicURL string, limits celenv.Limits,
	clk clock.Clock, log *slog.Logger,
) *authzenEndpoint {
	if log == nil {
		log = pclog.Discard()
	}
	e := &authzenEndpoint{
		pool: pool, authn: authn, decider: decider, publicURL: strings.TrimRight(publicURL, "/"),
		mappers: newMapperCache(limits), rates: newPointRates(clk), log: log,
	}
	if pool != nil {
		// Each point's rate holds across replicas (G0 M13 D9, HR-376).
		e.rates = sharedPointRates{ratelimit.NewStore(pool)}
	}
	e.pointOf = e.activePoint
	return e
}

// mount installs the endpoint on mux.
func (e *authzenEndpoint) mount(mux *http.ServeMux) {
	mux.HandleFunc(http.MethodGet+" "+authzenConfigPath, e.configuration)
	mux.HandleFunc(http.MethodPost+" "+authzenEvaluationPath, func(w http.ResponseWriter, r *http.Request) { e.serve(w, r, false) })
	mux.HandleFunc(http.MethodPost+" "+authzenEvaluationsPath, func(w http.ResponseWriter, r *http.Request) { e.serve(w, r, true) })
}

// authzenMetadata is the PDP metadata (AuthZEN 1.0 §13).
type authzenMetadata struct {
	PolicyDecisionPoint       string   `json:"policy_decision_point"`
	AccessEvaluationEndpoint  string   `json:"access_evaluation_endpoint"`
	AccessEvaluationsEndpoint string   `json:"access_evaluations_endpoint"`
	Capabilities              []string `json:"capabilities"`
}

func (e *authzenEndpoint) configuration(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_ = json.MarshalWrite(w, authzenMetadata{
		PolicyDecisionPoint: e.publicURL, AccessEvaluationEndpoint: e.publicURL + authzenEvaluationPath,
		AccessEvaluationsEndpoint: e.publicURL + authzenEvaluationsPath, Capabilities: []string{AuthZENCapability},
	})
}

type authzenProblem struct {
	Error string `json:"error"`
}

func authzenReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, v)
}

func authzenRefuse(w http.ResponseWriter, status int, code string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="pantherclaw", error="invalid_token"`)
	}
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "1")
	}
	authzenReply(w, status, authzenProblem{Error: code})
}

// point is the enforcement point asking.
type point struct {
	Org  ids.OrgID
	ID   ids.UUID
	Name string
	Rate int
	// Subject is the point's service account.
	Subject ids.UUID
}

// errNotPoint: the caller is not an ACTIVE enforcement point.
var errNotPoint = errors.New("authzen: not an active enforcement point")

// authenticate resolves the bearer to an ACTIVE enforcement point: an
// access token of a service account holding authzen.evaluate on its org
// that is the subject of an ACTIVE point (D26).
func (e *authzenEndpoint) authenticate(ctx context.Context, r *http.Request) (point, error) {
	bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || bearer == "" {
		return point{}, errNotPoint
	}
	c, err := e.authn.Authenticate(ctx, bearer)
	if err != nil {
		if errors.Is(err, tapp.ErrNoCaller) || isUnauthenticated(err) {
			return point{}, errNotPoint
		}
		return point{}, err
	}
	if c.Human() || c.Principal.Kind != td.KindServiceAccount || c.Credential != tapp.CredAccessToken ||
		c.Require(td.PermAuthZENEvaluate, td.OrgPath(c.Org)) != nil {
		return point{}, errNotPoint
	}
	return e.pointOf(ctx, c)
}

// activePoint is the ACTIVE point whose subject is the caller (D26).
func (e *authzenEndpoint) activePoint(ctx context.Context, c tapp.Caller) (point, error) {
	var p point
	err := e.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		row, err := dbq.New(tx).ActiveEnforcementPointOf(ctx, c.Org, c.Principal.ID)
		if db.IsNoRows(err) {
			return errNotPoint
		} else if err != nil {
			return err
		}
		p = point{Org: c.Org, ID: row.ID, Name: row.Name, Rate: int(row.RatePerSecond), Subject: c.Principal.ID}
		return nil
	}, db.ReadOnly())
	return p, err
}

// serve answers one evaluation request or one batch.
func (e *authzenEndpoint) serve(w http.ResponseWriter, r *http.Request, batch bool) {
	ctx := r.Context()
	if id := r.Header.Get("X-Request-ID"); id != "" && len(id) <= 128 && !strings.ContainsFunc(id, isCtl) {
		w.Header().Set("X-Request-ID", id)
	}
	p, err := e.authenticate(ctx, r)
	switch {
	case errors.Is(err, errNotPoint):
		authzenRefuse(w, http.StatusUnauthorized, authzenUnauthorized)
		return
	case err != nil:
		e.log.ErrorContext(ctx, "authzen.authentication_unavailable", pclog.Err(err))
		authzenRefuse(w, http.StatusServiceUnavailable, authzenUnavailable)
		return
	}
	// The request itself is JSON in UTF-8 and nothing else (D113).
	if !jsonContent(r.Header.Get("Content-Type"), []byte{0}) || len(r.Header.Values("Content-Type")) != 1 {
		authzenRefuse(w, http.StatusUnsupportedMediaType, authzenMediaType)
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, authzenMaxBody))
	if err != nil {
		if errors.As(err, new(*http.MaxBytesError)) {
			authzenRefuse(w, http.StatusRequestEntityTooLarge, authzenTooLarge)
			return
		}
		authzenRefuse(w, http.StatusBadRequest, authzenInvalid)
		return
	}
	evals, semantic, err := parseAuthZEN(body, batch)
	if err != nil {
		authzenRefuse(w, http.StatusBadRequest, authzenInvalid)
		return
	}
	if ok, err := e.rates.allowPoint(ctx, p, len(evals)); err != nil || !ok {
		if err != nil {
			// The shared counter is unavailable: refuse (HR-376).
			e.log.ErrorContext(ctx, "authzen.rate_unavailable", slog.String("point", p.ID.String()), pclog.Err(err))
		}
		authzenRefuse(w, http.StatusTooManyRequests, authzenRateLimited)
		return
	}
	conns, err := e.connections(ctx, p, evals)
	switch {
	case errors.Is(err, errNotBound):
		authzenRefuse(w, http.StatusForbidden, authzenForbidden)
		return
	case err != nil:
		e.log.ErrorContext(ctx, "authzen.connections_unavailable", pclog.Err(err))
		authzenRefuse(w, http.StatusServiceUnavailable, authzenUnavailable)
		return
	}
	var out []authzenResponse
	// One proof decides at most one evaluation (D82).
	seen := map[string]bool{}
	for i, ev := range evals {
		var res authzenResponse
		var err error
		if proof := proofOf(ev); proof != "" && seen[proof] {
			res = refusal(codeProofUsed)
		} else {
			seen[proof] = proof != ""
			res, err = e.evaluate(ctx, p, conns[i], ev)
		}
		if err != nil {
			e.log.ErrorContext(ctx, "authzen.decision_unavailable", slog.String("enforcement_point_id", p.ID.String()), pclog.Err(err))
			res = authzenDenied(authority.ExternalCannotAuthorize, "AUTHORITY_UNAVAILABLE", "PantherClaw could not decide; try again.")
		}
		out = append(out, res)
		if (semantic == semanticDenyOnFirstDeny && !res.Decision) || (semantic == semanticPermitOnFirstPermit && res.Decision) {
			break
		}
	}
	if !batch {
		authzenReply(w, http.StatusOK, out[0])
		return
	}
	authzenReply(w, http.StatusOK, struct {
		Evaluations []authzenResponse `json:"evaluations"`
	}{Evaluations: out})
}

func isCtl(r rune) bool { return r < 0x20 || r == 0x7f }

// pointLimiter counts a point's evaluations a second (HR-321); an error
// refuses the request (HR-376).
type pointLimiter interface {
	allowPoint(ctx context.Context, p point, n int) (bool, error)
}

// scopeAuthZENPoint is the shared counter's scope of a point's rate.
const scopeAuthZENPoint = "authzen.point"

// sharedPointRates counts each point's evaluations a second in the shared
// limiter, so the rate holds across every replica (G0 M13 D9, HR-376).
type sharedPointRates struct{ l ratelimit.Limiter }

func (s sharedPointRates) allowPoint(ctx context.Context, p point, n int) (bool, error) {
	d, err := s.l.Take(ctx, scopeAuthZENPoint, p.Org.String()+"/"+p.ID.String(), time.Second, n, p.Rate)
	return d.Allowed, err
}

// pointRates limits each point's evaluations a second on this instance
// (HR-321): a one-second window per point, its points kept in a bounded
// least-recently-used list, so one point's window never resets
// another's (D82). The server uses sharedPointRates; pointRates serves an
// endpoint without a database (tests).
type pointRates struct {
	mu    sync.Mutex
	clock clock.Clock
	max   int
	order *list.List // of *pointWindow, most recent first
	by    map[ids.UUID]*list.Element
}

type pointWindow struct {
	point ids.UUID
	start time.Time
	count int
}

func newPointRates(clk clock.Clock) *pointRates {
	if clk == nil {
		clk = clock.System{}
	}
	return &pointRates{clock: clk, max: 10_000, order: list.New(), by: map[ids.UUID]*list.Element{}}
}

func (l *pointRates) allowPoint(_ context.Context, p point, n int) (bool, error) {
	return l.allow(p.ID, p.Rate, n), nil
}

// allow records n evaluations for a point and reports whether they fit.
func (l *pointRates) allow(p ids.UUID, rate, n int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock.Now()
	el, ok := l.by[p]
	if ok {
		l.order.MoveToFront(el)
	} else {
		el = l.order.PushFront(&pointWindow{point: p, start: now})
		l.by[p] = el
		if l.order.Len() > l.max {
			old := l.order.Back()
			l.order.Remove(old)
			delete(l.by, old.Value.(*pointWindow).point)
		}
	}
	w := el.Value.(*pointWindow)
	if now.Sub(w.start) >= time.Second {
		w.start, w.count = now, 0
	}
	if w.count+n > rate {
		return false
	}
	w.count += n
	return true
}

// authzenResponse is one decision (AuthZEN 1.0 §7.2).
type authzenResponse struct {
	Decision bool           `json:"decision"`
	Context  authzenContext `json:"context"`
}

// authzenContext is PantherClaw's explanation of a decision (D28).
type authzenContext struct {
	PantherClaw authzenFacts      `json:"pantherclaw"`
	ReasonUser  map[string]string `json:"reason_user,omitempty"`
}

type authzenFacts struct {
	Outcome       string       `json:"outcome"`
	Code          string       `json:"code,omitempty"`
	TransactionID string       `json:"transaction_id,omitempty"`
	ActionID      string       `json:"action_id,omitempty"`
	Receipt       string       `json:"receipt,omitempty"`
	Coverage      string       `json:"coverage"`
	Wait          *authzenWait `json:"wait,omitempty"`
	ActionToken   string       `json:"action_token,omitempty"`
	// Nonce is the org's current PAP/1 nonce, for the enforcement point to
	// pass to the agent as PAP-Nonce.
	Nonce string `json:"nonce,omitempty"`
}

type authzenWait struct {
	Handle   string `json:"handle"`
	Deadline string `json:"deadline,omitempty"`
}

// authzenDenied is a refusal decided before or instead of the Authority.
func authzenDenied(outcome, code, reason string) authzenResponse {
	return authzenResponse{Context: authzenContext{
		PantherClaw: authzenFacts{Outcome: outcome, Code: code, Coverage: "PARTIAL"},
		ReasonUser:  map[string]string{"en": reason},
	}}
}

// jsonObject reports whether v is a JSON object.
func jsonObject(v jsontext.Value) bool { return len(v) > 0 && v.Kind() == '{' }
