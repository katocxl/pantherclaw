// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sdk is the gateway's face for agent SDKs (G0 M8 decision 1;
// HR-201, HR-200): POST /sdk/{connection} asks for a decision about a raw
// tool call that the agent runs itself, such as one a Claude Agent SDK
// PreToolUse hook intercepted.
//
// It serves http and mcp connections whose access mode is agent_held or
// target_enforced (brief design decision 9). On a pantherclaw_held
// connection the gateway holds the credential, so the agent uses the
// gateway's MCP or HTTP face instead (USE_GATEWAY_FACE, HR-186); shell
// commands go to the hook face (HR-200).
//
// The request carries PAP/1 credentials and the raw call: the tool's name
// as the agent sees it, the MCP server's name for an MCP tool, its input
// and the SDK's id of the call. The gateway maps mcp__{server}__{tool}
// through the connection's package's MCP mapping of the tool and reads
// nothing the SDK computed (an ActionIR, a hash, a canonical form). The
// action's channel is sdk, and it goes down the one dispatch path:
// Authorize, and for an allowed action BeginDispatch and RecordExecution
// with outcome DELEGATED. On a target-enforced connection the gateway also
// re-serializes the outbound request and returns it with the action token
// that binds its body, which the SDK sends unchanged (HR-201, HR-188).
//
// The answer is allow only for an action the gateway recorded as
// delegated, hold with the wait handle for a held one, and deny for
// everything else, each labeled PARTIAL (HR-024, HR-186), with the action's
// id, its canonical form and hash. A tool the agent SDK has built in
// (Read, Edit, Bash in an application that only observes the shell, …)
// has no mapping (G0 M8 decision 2): the Authority verifies the workload in
// its run and records the call in tool_observations, and the face answers
// allow, labeled OBSERVE_ONLY. An MCP tool the package does not map is
// never allowed.
package sdk

import (
	"encoding/base64"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxBody is the largest request body read (the brief's contract).
const MaxBody = 64 << 10

// Coverage labels of an answer (HR-024, HR-200).
const (
	// CoveragePartial: a decided call the agent performs itself.
	CoveragePartial = "PARTIAL"
	// CoverageObserveOnly: an unmapped built-in tool, recorded and not
	// decided.
	CoverageObserveOnly = "OBSERVE_ONLY"
)

// Codes of calls refused before the Authority decides them.
const (
	// CodeUnknownTool: the connection's package does not map the tool, or
	// the name is neither an MCP tool nor a built-in tool.
	CodeUnknownTool = "unknown_tool"
	// CodeInvalidInput: the input does not fit the reviewed mapping.
	CodeInvalidInput = "invalid_input"
	// CodeUseGatewayFace: the gateway holds the connection's credential,
	// so the agent calls it through the gateway's MCP or HTTP face.
	CodeUseGatewayFace = "use_gateway_face"
	// CodeUnknownServer: the MCP server is not the one the connection
	// governs, the server named after the connection.
	CodeUnknownServer = "unknown_server"
	// CodeConnectionNotServed: the Authority does not have this gateway
	// serving the connection (its configuration is stale), so a built-in
	// tool call cannot be recorded.
	CodeConnectionNotServed = "connection_not_served"
)

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves POST /sdk/{connection}.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	publicURL string
	log       *slog.Logger
}

// New returns the SDK face. publicURL is the gateway's base URL, which
// proofs are checked against.
func New(engine *dispatch.Engine, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Path returns the connection a request path names: "/sdk/{connection}".
func Path(escapedPath string) (string, bool) {
	name, ok := strings.CutPrefix(escapedPath, "/sdk/")
	return name, ok && name != "" && !strings.Contains(name, "/")
}

// Request is an SDK's raw tool call.
type Request struct {
	// Tool is the tool's name as the agent sees it: mcp__{server}__{tool}
	// for an MCP tool, or the name of a tool the agent SDK has built in.
	Tool string `json:"tool"`
	// Server is the MCP server's name, set exactly for an MCP tool.
	Server string `json:"server,omitzero"`
	// Input is the tool's input as the agent produced it.
	Input jsontext.Value `json:"input"`
	// ToolUseID is the SDK's id of this call.
	ToolUseID string `json:"tool_use_id"`
}

// Answer is the gateway's answer.
type Answer struct {
	// Decision is "allow", "hold" or "deny".
	Decision string `json:"decision"`
	// Reason is for the person and the agent: why, and what to do.
	Reason string `json:"reason"`
	// ErrorClass and Code say why a call was not allowed (F642).
	ErrorClass string   `json:"error_class,omitzero"`
	Code       string   `json:"code,omitzero"`
	Reasons    []string `json:"reasons,omitzero"`
	// ActionID is the action's id: send it again as PC-Action-Id to
	// resubmit the same call. ActionHash is the hex SHA-256 of the action
	// the gateway mapped, and ActionIR that action's canonical JSON
	// (base64url, no padding), so the SDK can check the hash and show what
	// was decided. Neither is ever read back from an SDK (HR-201).
	ActionID      string `json:"action_id,omitzero"`
	ActionHash    string `json:"action_hash,omitzero"`
	ActionIR      string `json:"action_ir,omitzero"`
	TransactionID string `json:"transaction_id,omitzero"`
	Receipt       string `json:"receipt,omitzero"`
	// Mode is "enforce", or "monitor" when the answer prevented nothing.
	Mode     string `json:"mode"`
	Coverage string `json:"coverage"`
	// Wait is a held call's wait handle.
	Wait *Wait `json:"wait,omitzero"`
	// Dispatch is, for an allowed call to a target-enforced connection,
	// the request the SDK sends unchanged (HR-201).
	Dispatch *Dispatch `json:"dispatch,omitzero"`
}

// Wait is a held call's wait handle (PAP-1 §8): long-poll
// WorkloadService.Wait with the handle, and once it is READY send the
// identical call again with the same PC-Action-Id.
type Wait struct {
	Handle            string `json:"handle"`
	State             string `json:"state,omitzero"`
	RetryAfterSeconds int32  `json:"retry_after_seconds,omitzero"`
	Deadline          string `json:"deadline,omitzero"`
	ConsumeBy         string `json:"consume_by,omitzero"`
	ApprovalRequestID string `json:"approval_request_id,omitzero"`
	Code              string `json:"code,omitzero"`
}

// Dispatch is the gateway's re-serialization of the action for a
// target-enforced connection (HR-075), with the action token whose bh is
// the lowercase hex SHA-256 of the decoded body (HR-188).
type Dispatch struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	ActionToken string            `json:"action_token"`
}

var (
	callRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	serverRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	builtinRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

func answer(w http.ResponseWriter, status int, a Answer) {
	if a.Mode == "" {
		a.Mode = "enforce"
	}
	if a.Coverage == "" {
		a.Coverage = CoveragePartial
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, a, json.Deterministic(true))
}

func deny(w http.ResponseWriter, status int, class dispatch.Class, code, reason string) {
	answer(w, status, Answer{Decision: "deny", Reason: reason, ErrorClass: string(class), Code: code})
}

// serves reports whether the face serves a connection, and when the
// connection exists but is not one an SDK reaches directly, why.
func serves(conn *control.Connection) (ok, useGateway bool) {
	if conn == nil || conn.Mapper == nil || (conn.GetKind() != "http" && conn.GetKind() != "mcp") {
		return false, false
	}
	switch conn.GetAccessMode() {
	case "agent_held", "target_enforced":
		return true, false
	}
	return false, true
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		deny(w, http.StatusMethodNotAllowed, dispatch.CannotAuthorize, "method_not_allowed", "the SDK endpoint takes POST only")
		return
	}
	if r.Header.Get("Origin") != "" {
		// An SDK client is never a browser.
		deny(w, http.StatusForbidden, dispatch.CannotAuthorize, "origin_not_allowed", "browsers may not call the SDK endpoint")
		return
	}
	name, _ := Path(r.URL.EscapedPath())
	var conn *control.Connection
	cfg := h.config.Current()
	if cfg != nil {
		conn = cfg.ByName[name]
	}
	ok, useGateway := serves(conn)
	switch {
	case useGateway:
		deny(w, http.StatusOK, dispatch.CannotAuthorize, CodeUseGatewayFace,
			"PantherClaw holds this connection's credential: call it through the gateway's MCP or HTTP face.")
		return
	case !ok:
		deny(w, http.StatusNotFound, dispatch.CannotAuthorize, "unknown_connection", "no connection of that name serves SDKs")
		return
	}
	// The raw body is hashed before anything parses it (HR-091).
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		deny(w, http.StatusRequestEntityTooLarge, dispatch.CannotAuthorize, "request_too_large", "the request is too large")
		return
	}
	var req Request
	if !jsontext.Value(body).IsValid() || json.Unmarshal(body, &req, json.RejectUnknownMembers(true)) != nil || req.Tool == "" ||
		req.Input.Kind() != '{' || !callRe.MatchString(req.ToolUseID) {
		deny(w, http.StatusBadRequest, dispatch.CannotAuthorize, "invalid_request",
			`the body must be {"tool": NAME, "input": {...}, "tool_use_id": ID}, with "server" for an MCP tool`)
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
	tool, err := mcpTool(req)
	switch {
	case errors.Is(err, errBuiltIn):
		h.observe(w, r, conn, in, req.Tool, req.Input)
		return
	case errors.Is(err, errUnknown):
		answer(w, http.StatusOK, Answer{
			Decision: "deny", ErrorClass: string(dispatch.CannotAuthorize), Code: CodeUnknownTool,
			Reason: "PantherClaw cannot decide this call: " + req.Tool + " is neither an MCP tool nor a tool the agent SDK has built in.",
		})
		return
	case err != nil:
		deny(w, http.StatusBadRequest, dispatch.CannotAuthorize, "invalid_request",
			`an MCP tool is "mcp__" + server + "__" + name with that "server"; a built-in tool has no "server"`)
		return
	case req.Server != name:
		// The connection governs one MCP server, named after it: a tool of
		// another server is never decided as this connection's.
		answer(w, http.StatusOK, Answer{
			Decision: "deny", ErrorClass: string(dispatch.CannotAuthorize), Code: CodeUnknownServer,
			Reason: "PantherClaw cannot decide this call: the MCP server " + req.Server + " is not the one connection " + name + " governs.",
		})
		return
	}
	action := in.Action
	if action == "" {
		action = ids.NewV7().String()
	}
	parsed, err := conn.Mapper.SDK(r.Context(), mapping.Context{
		Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}, tool, req.Input)
	if err != nil {
		// A tool the reviewed package does not map, or input that does not
		// fit it (an unknown member, a control character): never allowed
		// (HR-200, HR-201).
		code, why := CodeInvalidInput, "its input does not match the reviewed mapping of "+req.Tool
		if errors.Is(err, mapping.ErrUnmapped) {
			code, why = CodeUnknownTool, "the connection's reviewed package does not map "+req.Tool
		}
		answer(w, http.StatusOK, Answer{
			Decision: "deny", Reason: "PantherClaw cannot decide this call: " + why + ".", ErrorClass: string(dispatch.CannotAuthorize),
			Code: code, ActionID: action,
		})
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
	a := decide(res)
	a.ActionID, a.ActionHash, a.ActionIR = action, parsed.HashHex(), base64.RawURLEncoding.EncodeToString(parsed.Canonical)
	answer(w, http.StatusOK, a)
}

// Why a raw call names no MCP tool.
var (
	// errBuiltIn: a tool the agent SDK has built in (observed only).
	errBuiltIn = errors.New("sdk: a built-in tool")
	// errUnknown: a name that is neither an MCP tool nor a built-in tool.
	errUnknown = errors.New("sdk: an unknown tool")
	// errShape: the call's members do not fit its kind of tool.
	errShape = errors.New("sdk: the call's members do not fit its tool")
)

// builtIns are the tools the Claude Agent SDK has built in, in the range the
// integration supports, with Bash and PowerShell for an application whose
// shell is only observed: the only names answered OBSERVE_ONLY. Any other
// name that is not an MCP tool is unknown_tool, so a client that obeys the
// face never runs an unmapped tool that is not built in (HR-200).
var builtIns = map[string]bool{
	"Agent": true, "Task": true, "Bash": true, "BashOutput": true, "KillShell": true, "KillBash": true, "PowerShell": true,
	"Read": true, "Write": true, "Edit": true, "MultiEdit": true, "Glob": true, "Grep": true, "LS": true,
	"NotebookRead": true, "NotebookEdit": true, "TodoWrite": true, "WebFetch": true, "WebSearch": true,
	"ExitPlanMode": true, "ListMcpResources": true, "ReadMcpResource": true, "SlashCommand": true, "Skill": true,
	"AskUserQuestion": true,
}

// mcpTool is the MCP tool a raw call names: mcp__{server}__{tool} with that
// server. A call with a built-in tool's name and no server is errBuiltIn,
// one with another such name errUnknown; an MCP call that does not fit is
// never observed instead of decided.
func mcpTool(req Request) (string, error) {
	rest, isMCP := strings.CutPrefix(req.Tool, "mcp__")
	if !isMCP {
		switch {
		case req.Server != "" || !builtinRe.MatchString(req.Tool):
			return "", errShape
		case builtIns[req.Tool]:
			return "", errBuiltIn
		}
		return "", errUnknown
	}
	name, found := strings.CutPrefix(rest, req.Server+"__")
	if !found || name == "" || !serverRe.MatchString(req.Server) {
		return "", errShape
	}
	return name, nil
}

// decide is the answer to a decision: allow only when the action was
// recorded as delegated (HR-186), with the request to send for a
// target-enforced connection.
func decide(res dispatch.Result) Answer {
	a := Answer{
		TransactionID: res.TransactionID, Reasons: res.Reasons, Receipt: res.Receipt, ErrorClass: string(res.Class), Code: res.Code,
	}
	if res.Monitor {
		a.Mode = "monitor"
	}
	txn := ""
	if res.TransactionID != "" {
		txn = " Transaction " + res.TransactionID + "."
	}
	switch {
	case res.Class == "" && res.Outcome == pb.Outcome_OUTCOME_DELEGATED:
		a.Decision, a.Reason = "allow", "PantherClaw allowed this call."+txn
		if res.Monitor {
			a.Reason = "PantherClaw is monitoring this route: the call is recorded, not decided." + txn
		}
		if d := res.Delegated; d != nil {
			a.Dispatch = &Dispatch{
				Method: d.Method, URL: d.URL, Headers: d.Headers, Body: base64.RawURLEncoding.EncodeToString(d.Body), ActionToken: d.ActionToken,
			}
			a.Reason += " Send the dispatch request exactly as given."
		}
	case res.Class == dispatch.Held:
		a.Decision, a.Wait = "hold", wait(res)
		a.Reason = "PantherClaw holds this call for an approval or a step-up by an eligible person." + txn +
			" Wait on the handle, then send the same call again with the same action id."
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

// wait is a held call's wait handle. The handle is the transaction id
// (G0 M5 part 2 design decision 15).
func wait(res dispatch.Result) *Wait {
	w := res.Wait
	out := &Wait{
		Handle: w.GetHandle(), RetryAfterSeconds: w.GetRetryAfterSeconds(), ApprovalRequestID: w.GetApprovalRequestId(), Code: w.GetCode(),
		Deadline: stamp(w.GetDeadlineTime()), ConsumeBy: stamp(w.GetConsumeByTime()),
	}
	if out.Handle == "" {
		out.Handle = res.TransactionID
	}
	if s := w.GetState(); s != pb.WaitState_WAIT_STATE_UNSPECIFIED {
		out.State = strings.TrimPrefix(s.String(), "WAIT_STATE_")
	}
	return out
}

// stamp is t in RFC 3339 UTC, "" when unset.
func stamp(t *timestamppb.Timestamp) string {
	if !t.IsValid() {
		return ""
	}
	return t.AsTime().UTC().Format(time.RFC3339)
}

// observe answers a built-in tool (G0 M8 decision 2): allowed and
// recorded OBSERVE_ONLY (its name and input digest) by the Authority,
// which verified the workload in its run (HR-200, HR-021).
func (h *Handler) observe(w http.ResponseWriter, r *http.Request, conn *control.Connection, in dispatch.Inbound, tool string, input []byte) {
	v, err := h.engine.Observe(r.Context(), in.Creds, in.Run, conn.GetId(), tool, input)
	if err != nil {
		h.log.ErrorContext(r.Context(), "gateway.authority_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		deny(w, http.StatusOK, dispatch.CannotAuthorize, dispatch.CodeAuthorityUnavailable, "PantherClaw cannot verify this workload now.")
		return
	}
	if !v.OK && v.Code == CodeConnectionNotServed {
		if v.Nonce != "" {
			w.Header().Set(dispatch.HeaderNonce, v.Nonce)
		}
		h.log.WarnContext(r.Context(), "gateway.sdk_connection_not_served", slog.String("connection_id", conn.GetId()))
		deny(w, http.StatusOK, dispatch.CannotAuthorize, CodeConnectionNotServed,
			"PantherClaw does not have this gateway serving the connection now, so the call cannot be recorded.")
		return
	}
	if !v.OK {
		h.refusePAP(w, r, v.Code, v.Nonce)
		return
	}
	if v.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, v.Nonce)
	}
	h.log.InfoContext(r.Context(), "gateway.sdk_observed", slog.String("connection_id", conn.GetId()), slog.String("tool", tool),
		slog.String("run_id", in.Run), slog.String("instance_id", v.Instance))
	answer(w, http.StatusOK, Answer{
		Decision: "allow", Mode: "monitor", Coverage: CoverageObserveOnly,
		Reason: "PantherClaw does not map the " + tool + " tool: the call is recorded, not decided.",
	})
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
