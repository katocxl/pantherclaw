// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package sdk is the gateway's face for agent SDKs (G0 M8 decision 1;
// HR-201, HR-200): POST /sdk/{connection} on a kind-local connection asks
// for a decision about a raw tool call that the agent runs itself, such as
// one a Claude Agent SDK PreToolUse hook intercepted.
//
// The request carries PAP/1 credentials and the raw call: the tool's name
// as the agent sees it, its input, the MCP server's name for an MCP tool,
// the SDK's id of the call and, for a shell tool, the working directory.
// The gateway maps it itself through the connection's reviewed package and
// reads nothing the SDK computed (an ActionIR, a hash, a canonical form):
// Bash and PowerShell through the hook mapping `shell` (pc.shell), adapted
// as `pclaw hook claude-code` adapts them, and mcp__{server}__{tool}
// through the package's MCP mapping of the tool. The action's channel is
// sdk, and it goes down the one dispatch path like a hook call: Authorize,
// and for an allowed action BeginDispatch and RecordExecution with outcome
// DELEGATED. The answer is allow only for an action the gateway recorded
// as delegated, hold with the wait handle for a held one, and deny for
// everything else. Every answer is labeled PARTIAL: the agent performs the
// action with its own access (HR-024, HR-186).
//
// The SDK's other built-in tools (Read, Edit, WebFetch, …) have no mapping
// (G0 M8 decision 2): the gateway verifies the workload and its run, logs
// the call and answers allow, labeled OBSERVE_ONLY. An MCP tool or a shell
// tool the package does not map is never allowed.
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

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxBody is the largest request body read, as on the MCP face.
const MaxBody = 256 << 10

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
	// CodeUnknownTool: the connection's package does not map the tool.
	CodeUnknownTool = "unknown_tool"
	// CodeInvalidInput: the input does not fit the reviewed mapping.
	CodeInvalidInput = "invalid_input"
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
	// Tool is the tool's name as the agent sees it: a built-in tool such as
	// Bash, or mcp__{server}__{tool}.
	Tool string `json:"tool"`
	// Server is the MCP server's name, set exactly for an MCP tool.
	Server string `json:"server,omitzero"`
	// Input is the tool's input as the agent produced it.
	Input jsontext.Value `json:"input"`
	// ToolUseID is the SDK's id of this call.
	ToolUseID string `json:"tool_use_id"`
	// Cwd is a shell tool's working directory, absolute and in its final
	// form; set exactly for a shell tool.
	Cwd string `json:"cwd,omitzero"`
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

var (
	// callRe is pc.shell's pattern of a call id.
	callRe    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	serverRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)
	builtinRe = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)
)

// shells are the built-in tools adapted to pc.shell's hook mapping, by the
// shell each runs.
var shells = map[string]string{"Bash": "bash", "PowerShell": "powershell"}

// shellInput is a shell tool's input. Besides the command it may carry
// only members that do not change the command that runs; any other member
// makes the call one PantherClaw cannot decide.
type shellInput struct {
	Command         string   `json:"command"`
	Description     *string  `json:"description"`
	Timeout         *float64 `json:"timeout"`
	RunInBackground *bool    `json:"run_in_background"`
}

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
	if conn == nil || conn.Mapper == nil || conn.GetKind() != "local" {
		deny(w, http.StatusNotFound, dispatch.CannotAuthorize, "unknown_connection", "no cooperative connection of that name")
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
			`the body must be {"tool": NAME, "input": {...}, "tool_use_id": ID} with "server" for an MCP tool and "cwd" for a shell tool`)
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
	via, tool, input, err := adapt(req)
	switch {
	case errors.Is(err, errBuiltIn):
		h.observe(w, r, conn, in, req.Tool)
		return
	case errors.Is(err, errShape):
		deny(w, http.StatusBadRequest, dispatch.CannotAuthorize, "invalid_request",
			`an MCP tool is "mcp__" + server + "__" + name with that "server" and no "cwd"; a shell tool has a "cwd" and no "server"`)
		return
	}
	var parsed actionir.Parsed
	if err == nil {
		parsed, err = conn.Mapper.SDK(r.Context(), mapping.Context{
			Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
		}, via, tool, input)
	}
	if err != nil {
		// A tool the reviewed package does not map, or input that does not
		// fit it (an unknown member, a device path, a control character):
		// never allowed (HR-200, HR-201).
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

// Why a raw call is not adapted.
var (
	// errBuiltIn: a built-in tool without a mapping (observed only).
	errBuiltIn = errors.New("sdk: an unmapped built-in tool")
	// errShape: the call's members do not fit its kind of tool.
	errShape = errors.New("sdk: the call's members do not fit its tool")
	// errInput: a shell tool's input does not fit pc.shell's mapping.
	errInput = errors.New("sdk: the input does not fit the reviewed mapping")
)

// adapt turns a raw call into the mapping it goes through: an MCP tool
// through the MCP mapping of its name with its input as sent, a shell tool
// through pc.shell's hook mapping with the input `pclaw hook claude-code`
// builds. Only a call that is neither, with a built-in tool's name and no
// server or working directory, is errBuiltIn: a shell or MCP call that does
// not fit is never observed instead of decided.
func adapt(req Request) (via defs.Channel, tool string, input []byte, err error) {
	if rest, mcp := strings.CutPrefix(req.Tool, "mcp__"); mcp {
		name, found := strings.CutPrefix(rest, req.Server+"__")
		if !found || name == "" || !serverRe.MatchString(req.Server) || req.Cwd != "" {
			return "", "", nil, errShape
		}
		return defs.ChannelMCP, name, req.Input, nil
	}
	shell, ok := shells[req.Tool]
	switch {
	case !ok && req.Server == "" && req.Cwd == "" && builtinRe.MatchString(req.Tool):
		return "", "", nil, errBuiltIn
	case !ok || req.Server != "" || req.Cwd == "":
		return "", "", nil, errShape
	}
	var s shellInput
	if json.Unmarshal(req.Input, &s, json.RejectUnknownMembers(true)) != nil || s.Command == "" {
		return "", "", nil, errInput
	}
	b, err := json.Marshal(map[string]string{"shell": shell, "command": s.Command, "cwd": req.Cwd, "call": req.ToolUseID},
		json.Deterministic(true))
	if err != nil {
		return "", "", nil, errInput
	}
	return defs.ChannelHook, "shell", b, nil
}

// decide is the answer to a decision: allow only when the action was
// recorded as delegated (HR-186).
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

// observe answers an unmapped built-in tool (G0 M8 decision 2): allowed
// and recorded OBSERVE_ONLY, for a workload the Authority verified in its
// run.
func (h *Handler) observe(w http.ResponseWriter, r *http.Request, conn *control.Connection, in dispatch.Inbound, tool string) {
	v, err := h.engine.Verify(r.Context(), in.Creds, in.Run)
	if err != nil {
		h.log.ErrorContext(r.Context(), "gateway.authority_unavailable", slog.String("connection_id", conn.GetId()), pclog.Err(err))
		deny(w, http.StatusOK, dispatch.CannotAuthorize, dispatch.CodeAuthorityUnavailable, "PantherClaw cannot verify this workload now.")
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
