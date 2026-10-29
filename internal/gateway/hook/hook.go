// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package hook is the gateway's cooperative face (G0 M6 design decision
// 16; HR-186, HR-187): POST /hook/{connection} on a kind-local connection
// asks for a decision about an action the agent's own machine will
// perform, such as a shell command a Claude Code hook intercepted
// (`pclaw hook claude-code`).
//
// The request carries PAP/1 credentials and names a hook mapping of the
// connection's reviewed package (pc.shell) with its input. The gateway maps
// it (working directories normalized lexically, device paths, alternate
// data streams and trailing dots or spaces refused; the command text never
// changed), and sends it down the one dispatch path: Authorize, and for an
// allowed action BeginDispatch and RecordExecution with outcome DELEGATED.
// The answer is allow only for an action the gateway recorded as
// delegated; everything else is deny with the reason and transaction, and
// a hold says where to approve, never asking the local user.
package hook

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxBody is the largest request body read.
const MaxBody = 64 << 10

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves POST /hook/{connection}.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	publicURL string
	log       *slog.Logger
}

// New returns the hook face. publicURL is the gateway's base URL, which
// proofs are checked against.
func New(engine *dispatch.Engine, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Path returns the connection a request path names: "/hook/{connection}".
func Path(escapedPath string) (string, bool) {
	name, ok := strings.CutPrefix(escapedPath, "/hook/")
	return name, ok && name != "" && !strings.Contains(name, "/")
}

// Request is a cooperative client's question: a hook mapping (the tool)
// and its input.
type Request struct {
	Tool  string         `json:"tool"`
	Input jsontext.Value `json:"input"`
}

// Answer is the gateway's answer.
type Answer struct {
	// Decision is "allow" or "deny".
	Decision string `json:"decision"`
	// Reason is for the person and the agent: why, and what to do.
	Reason string `json:"reason"`
	// ErrorClass and Code say why a call was denied (F642).
	ErrorClass    string   `json:"error_class,omitzero"`
	Code          string   `json:"code,omitzero"`
	Reasons       []string `json:"reasons,omitzero"`
	TransactionID string   `json:"transaction_id,omitzero"`
	// Held: the action waits for an approval or a step-up in PantherClaw.
	Held bool `json:"held,omitzero"`
	// Mode is "enforce", or "monitor" when the decision prevented nothing.
	Mode    string `json:"mode"`
	Receipt string `json:"receipt,omitzero"`
	// Explanation is the agent-safe explanation (F330, HR-400).
	Explanation *dispatch.Explanation `json:"explanation,omitzero"`
}

func answer(w http.ResponseWriter, status int, a Answer) {
	if a.Mode == "" {
		a.Mode = "enforce"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, a, json.Deterministic(true))
}

func deny(w http.ResponseWriter, status int, class dispatch.Class, code, reason string) {
	answer(w, status, Answer{Decision: "deny", Reason: reason, ErrorClass: string(class), Code: code})
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		deny(w, http.StatusMethodNotAllowed, dispatch.CannotAuthorize, "method_not_allowed", "the hook endpoint takes POST only")
		return
	}
	if r.Header.Get("Origin") != "" {
		// A hook client is never a browser.
		deny(w, http.StatusForbidden, dispatch.CannotAuthorize, "origin_not_allowed", "browsers may not call the hook endpoint")
		return
	}
	name, _ := Path(r.URL.EscapedPath())
	var conn *control.Connection
	cfg := h.config.Current()
	if cfg != nil {
		conn = cfg.ByName[name]
	}
	if conn == nil || conn.Mapper == nil || conn.GetKind() != "local" {
		deny(w, http.StatusNotFound, dispatch.CannotAuthorize, "unknown_connection", "no cooperative connection of that name")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		deny(w, http.StatusRequestEntityTooLarge, dispatch.CannotAuthorize, "request_too_large", "the request is too large")
		return
	}
	var req Request
	if !jsontext.Value(body).IsValid() || json.Unmarshal(body, &req, json.RejectUnknownMembers(true)) != nil || req.Tool == "" ||
		req.Input.Kind() != '{' {
		deny(w, http.StatusBadRequest, dispatch.CannotAuthorize, "invalid_request", `the body must be {"tool": NAME, "input": {...}}`)
		return
	}
	in := dispatch.ReadInbound(r, body, h.publicURL+r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(w, r, pap.CodeUseNonce, "")
		return
	case !in.HasToken:
		code, nonce := h.engine.ReportUnknown(r.Context(), in.Creds, r.UserAgent(), "")
		h.refusePAP(w, r, code, nonce)
		return
	case !in.SubjectOK:
		h.refusePAP(w, r, pap.CodeInvalidToken, "")
		return
	case in.Run == "":
		deny(w, http.StatusBadRequest, dispatch.CannotAuthorize, "run_required", "the "+dispatch.HeaderRunID+" header is required")
		return
	}
	action := in.Action
	if action == "" {
		action = ids.NewV7().String()
	}
	parsed, err := conn.Mapper.Hook(r.Context(), mapping.Context{
		Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}, req.Tool, req.Input)
	if err != nil {
		// Input the reviewed mapping refuses: an unknown tool, a device
		// path, an alternate data stream, a control character (HR-187).
		deny(w, http.StatusOK, dispatch.CannotAuthorize, "invalid_input",
			"PantherClaw cannot decide this call: its input does not match the reviewed "+req.Tool+" mapping.")
		return
	}
	res := h.engine.Dispatch(r.Context(), dispatch.Call{Connection: conn, Action: parsed, Workload: in.Creds})
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, res.PAPError, res.Nonce)
		return
	}
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	answer(w, http.StatusOK, decide(res))
}

// decide is the answer to a decision: allow only when the action was
// recorded as delegated (HR-186).
func decide(res dispatch.Result) Answer {
	a := Answer{
		TransactionID: res.TransactionID, Reasons: res.Reasons, Receipt: res.Receipt, ErrorClass: string(res.Class), Code: res.Code,
		Explanation: dispatch.ExplanationOf(res.Explanation),
	}
	if res.Monitor {
		a.Mode = "monitor"
	}
	txn := ""
	if res.TransactionID != "" {
		txn = " Transaction " + res.TransactionID + "."
	}
	switch {
	case res.Class == "" && res.Outcome != 0:
		a.Decision, a.Reason = "allow", "PantherClaw allowed this call."+txn
		if res.Monitor {
			a.Reason = "PantherClaw is monitoring this route: the call is recorded, not decided." + txn
		}
	case res.Class == dispatch.Held:
		a.Decision, a.Held = "deny", true
		a.Reason = "PantherClaw holds this call for an approval or a step-up by an eligible person, not by you." + txn +
			" Once it is approved in PantherClaw, run the same command again."
	default:
		a.Decision = "deny"
		a.Reason = "PantherClaw denied this call: " + string(res.Class)
		if res.Code != "" {
			a.Reason += " (" + res.Code + ")"
		}
		a.Reason += "." + txn
	}
	return a
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
	deny(w, http.StatusUnauthorized, dispatch.AuthenticationFailed, string(code), "PAP/1: "+string(code))
}
