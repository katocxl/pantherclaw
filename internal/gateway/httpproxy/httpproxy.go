// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package httpproxy is the gateway's HTTP face (G0 M6, ARCHITECTURE §9):
// `/{connection}/…` serves the HTTP routes of the connection's reviewed
// package (PN-003.5). A request's body is read and hashed, its PAP/1
// credentials are forwarded for the Authority to verify, and it is mapped
// through the package to ActionIR and sent down the one dispatch path.
// Nothing the agent sent reaches the target except through that mapping
// (HR-075).
//
// The target's answer comes back with its status and body (the credential
// removed) and only its Content-Type and request id; PantherClaw's own
// facts are PC-* headers. Every refusal is JSON with an error_class
// (design decision 18, F642).
package httpproxy

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxBody is the largest request body the face reads.
const MaxBody = 64 << 10

// Response headers.
const (
	HeaderTransaction     = "PC-Transaction-Id"
	HeaderOutcome         = "PC-Outcome"
	HeaderReceipt         = "PC-Receipt"
	HeaderMode            = "PC-Mode"
	HeaderDecision        = "PC-Decision"
	HeaderTruncated       = "PC-Truncated"
	HeaderTargetRequestID = "PC-Target-Request-Id"
)

// Codes of refusals made before dispatch.
const (
	CodeUnknownConnection = "unknown_connection"
	CodeUnknownRoute      = "unknown_route"
	CodeInvalidRequest    = "invalid_request"
	CodeBodyTooLarge      = "body_too_large"
	CodeIDsRequired       = "run_and_action_ids_required"
)

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves `/{connection}/…`.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	publicURL string
	log       *slog.Logger
}

// New returns the HTTP face. publicURL is the base URL workloads call:
// request proofs are checked against it, never against the Host header
// (PAP-1 §4).
func New(engine *dispatch.Engine, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Refusal is the JSON body of every refusal.
type Refusal struct {
	ErrorClass    string   `json:"error_class"`
	Error         string   `json:"error"`
	Decision      string   `json:"decision,omitempty"`
	Reasons       []string `json:"reasons,omitempty"`
	TransactionID string   `json:"transaction_id,omitempty"`
	// Monitor: the route runs in monitor mode; Decision was hypothetical.
	Monitor      bool           `json:"monitor,omitzero"`
	Outcome      string         `json:"outcome,omitempty"`
	TargetStatus int            `json:"target_status,omitzero"`
	Response     jsontext.Value `json:"response,omitempty"`
	Receipt      string         `json:"receipt,omitempty"`
}

func refuse(w http.ResponseWriter, status int, r Refusal) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, r)
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ctx := r.Context()
	name, rest, ok := split(r.URL.EscapedPath())
	cfg := h.config.Current()
	var conn *control.Connection
	if ok && cfg != nil {
		conn = cfg.ByName[name]
	}
	if conn == nil || conn.Mapper == nil {
		refuse(w, http.StatusNotFound, Refusal{ErrorClass: string(dispatch.CannotAuthorize), Error: CodeUnknownConnection})
		return
	}
	// The raw body is hashed before anything parses it (HR-091).
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w, http.StatusRequestEntityTooLarge, Refusal{ErrorClass: string(dispatch.CannotAuthorize), Error: CodeBodyTooLarge})
		return
	}
	in := dispatch.ReadInbound(r, body, h.publicURL+r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(w, r, pap.CodeUseNonce, "")
		return
	case !in.HasToken:
		route, _ := conn.Mapper.HTTPRoute(r.Method, rest)
		code, nonce := h.engine.ReportUnknown(ctx, in.Creds, r.UserAgent(), route)
		h.refusePAP(w, r, code, nonce)
		return
	case !in.SubjectOK:
		h.refusePAP(w, r, pap.CodeInvalidToken, "")
		return
	case in.Run == "" || in.Action == "":
		refuse(w, http.StatusBadRequest, Refusal{ErrorClass: string(dispatch.CannotAuthorize), Error: CodeIDsRequired})
		return
	}
	p, err := conn.Mapper.HTTPRequest(ctx, mapping.Context{
		Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: in.Action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}, r.Method, rest, r.URL.RawQuery, r.Header.Get("Content-Type"), body)
	switch {
	case errors.Is(err, mapping.ErrUnmapped):
		refuse(w, http.StatusNotFound, Refusal{ErrorClass: string(dispatch.CannotAuthorize), Error: CodeUnknownRoute})
		return
	case err != nil:
		refuse(w, http.StatusBadRequest, Refusal{
			ErrorClass: string(dispatch.CannotAuthorize), Error: CodeInvalidRequest, Decision: decision(pb.Decision_DECISION_CANNOT_AUTHORIZE),
		})
		return
	}
	built := time.Since(start)
	res := h.engine.Dispatch(ctx, dispatch.Call{Connection: conn, Action: p, Workload: in.Creds})
	timing(w, built, res.Timings, time.Since(start))
	h.write(w, r, res)
}

// split splits an escaped path into the connection name and the rest,
// which keeps its leading slash.
func split(escaped string) (name, rest string, ok bool) {
	s, found := strings.CutPrefix(escaped, "/")
	if !found {
		return "", "", false
	}
	i := strings.IndexByte(s, '/')
	if i <= 0 {
		return "", "", false
	}
	return s[:i], s[i:], true
}

func decision(d pb.Decision) string {
	if d == pb.Decision_DECISION_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(d.String(), "DECISION_")
}

func outcome(o pb.Outcome) string {
	if o == pb.Outcome_OUTCOME_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(o.String(), "OUTCOME_")
}

// refusePAP answers 401 with a PAP-Error code and a nonce (PAP-1 §12).
func (h *Handler) refusePAP(w http.ResponseWriter, r *http.Request, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = h.engine.Nonce(r.Context())
	}
	if nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, nonce)
	}
	w.Header().Set(dispatch.HeaderError, string(code))
	refuse(w, http.StatusUnauthorized, Refusal{ErrorClass: string(dispatch.AuthenticationFailed), Error: string(code)})
}

func timing(w http.ResponseWriter, built time.Duration, laps []dispatch.Lap, total time.Duration) {
	ms := func(d time.Duration) string { return fmt.Sprintf("%.3f", float64(d.Microseconds())/1000) }
	w.Header().Add("Server-Timing", "build;dur="+ms(built))
	for _, l := range laps {
		w.Header().Add("Server-Timing", l.Name+";dur="+ms(l.D))
	}
	w.Header().Add("Server-Timing", "total;dur="+ms(total))
}

// write answers with the target's response, or a refusal.
func (h *Handler) write(w http.ResponseWriter, r *http.Request, res dispatch.Result) {
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	if res.TransactionID != "" {
		w.Header().Set(HeaderTransaction, res.TransactionID)
	}
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, res.PAPError, res.Nonce)
		return
	}
	mode := "enforce"
	if res.Monitor {
		mode = "monitor"
	}
	w.Header().Set(HeaderMode, mode)
	if res.Class == "" && res.Response != nil {
		hdr := w.Header()
		if o := outcome(res.Outcome); o != "" {
			hdr.Set(HeaderOutcome, o)
		}
		if res.Receipt != "" {
			hdr.Set(HeaderReceipt, res.Receipt)
		}
		hdr.Set(HeaderDecision, decision(res.Decision))
		if res.Response.ContentType != "" {
			hdr.Set("Content-Type", res.Response.ContentType)
		}
		if res.Response.RequestID != "" {
			hdr.Set(HeaderTargetRequestID, res.Response.RequestID)
		}
		if res.Response.Truncated {
			hdr.Set(HeaderTruncated, "true")
		}
		hdr.Set("Cache-Control", "no-store")
		hdr.Set("Content-Length", strconv.Itoa(len(res.Response.Body)))
		w.WriteHeader(res.Response.Status)
		_, _ = w.Write(res.Response.Body)
		return
	}
	out := Refusal{
		ErrorClass: string(res.Class), Error: res.Code, Decision: decision(res.Decision), Reasons: res.Reasons,
		TransactionID: res.TransactionID, Monitor: res.Monitor, Outcome: outcome(res.Outcome), Receipt: res.Receipt,
	}
	if res.Response != nil {
		out.TargetStatus = res.Response.Status
		if v := jsontext.Value(res.Response.Body); len(v) <= MaxBody && v.IsValid() {
			out.Response = v
		}
	}
	refuse(w, status(res), out)
}

// status is the HTTP status of a refusal.
func status(res dispatch.Result) int {
	switch res.Class {
	case dispatch.PolicyDenied, dispatch.Held:
		return http.StatusForbidden
	case dispatch.CannotAuthorize:
		switch res.Code {
		case dispatch.CodeAuthorityUnavailable:
			return http.StatusServiceUnavailable
		case dispatch.CodeDuplicate:
			return http.StatusConflict
		}
		return http.StatusForbidden
	case dispatch.EnforcementFailed:
		switch res.Code {
		case dispatch.CodeContainmentStale, dispatch.CodeGatewayRevoked, dispatch.CodeCircuitOpen:
			return http.StatusServiceUnavailable
		case dispatch.CodeKillSwitch, dispatch.CodeConnectionQuarantined:
			return http.StatusForbidden
		case dispatch.CodeEpochStale, dispatch.CodeDispatchRefused:
			return http.StatusConflict
		}
		return http.StatusBadGateway
	case dispatch.ToolFailed:
		// The target's own refusal keeps its status.
		if res.Response != nil && res.Response.Status >= 400 && res.Response.Status < 500 {
			return res.Response.Status
		}
		return http.StatusBadGateway
	case dispatch.Uncertain:
		if res.Code == dispatch.CodeNotRecorded {
			return http.StatusBadGateway
		}
		return http.StatusGatewayTimeout
	case dispatch.AuthenticationFailed:
		return http.StatusUnauthorized
	}
	// Accepted without a response: nothing to pass back.
	return http.StatusBadGateway
}
