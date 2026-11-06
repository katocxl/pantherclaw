// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package runtime is the gateway's face for cloud agent runtimes (G0 M34
// D994; HR-764, HR-765): POST /runtime/agentcore takes the raw request
// interceptor event of an Amazon Bedrock AgentCore gateway, sent by that
// gateway's interceptor Lambda (cmd/pc-agentcore-interceptor) with PAP/1
// credentials, and answers with the interceptor output the Lambda returns
// as is.
//
// The request carries PAP/1 credentials and the PC-Runtime-Gateway header
// naming the AgentCore gateway's ARN; a browser (any Origin) is refused.
// Of the event's MCP JSON-RPC request:
//   - tools/call is decided: params.name splits on its first "___" into the
//     AgentCore target and the tool; the connection is the one this gateway
//     serves whose runtime_target is "agentcore:<ARN>/<target>" (D991),
//     else RUNTIME_TARGET_UNKNOWN. Whether the ARN's account is the one the
//     instance was attested in is the Authority's check (D994a,
//     RUNTIME_ACCOUNT_MISMATCH). The call is mapped through the connection
//     package's MCP mapping of the tool with channel runtime (D990) and goes
//     down the one dispatch path; a runtime action is never forwarded, only
//     recorded as delegated (HR-760);
//   - initialize, ping, tools/list and notifications/* pass undecided;
//   - every other method is refused with a JSON-RPC error -32601
//     (RUNTIME_METHOD_NOT_DECIDED).
//
// An HTTP target's event is refused (RUNTIME_HTTP_NOT_SUPPORTED). Only an
// action recorded as delegated passes; a deny or a hold answers the MCP
// request with a tool error and never reaches the target. Every decision is
// cooperative and PARTIAL: the AgentCore gateway runs the tool, and one
// without the interceptor is not asked about (R-82).
package runtime

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// AgentCorePath is the AgentCore face's path.
const AgentCorePath = "/runtime/agentcore"

// MaxBody is the largest event read (D994).
const MaxBody = 1 << 20

// HeaderGateway names the AgentCore gateway's ARN.
const HeaderGateway = "PC-Runtime-Gateway"

// Codes of the face's refusals (D994).
const (
	CodeTargetUnknown     = "RUNTIME_TARGET_UNKNOWN"
	CodeMethodNotDecided  = "RUNTIME_METHOD_NOT_DECIDED"
	CodeHTTPNotSupported  = "RUNTIME_HTTP_NOT_SUPPORTED"
	CodeGatewayARNInvalid = "RUNTIME_GATEWAY_ARN_INVALID"
	CodeEventInvalid      = "RUNTIME_EVENT_INVALID"
)

// HeaderRunEnded is set on an answer whose decision found the run no longer
// active, so the interceptor starts a new one (D995).
const HeaderRunEnded = "PC-Run-Ended"

// reasonRunNotActive is the Authority's reason for a run that ended.
const reasonRunNotActive = "RUN_NOT_ACTIVE"

// HeldText is what a held call tells the agent (D994).
const HeldText = "held for a person's approval in PantherClaw; ask again after"

// TargetPrefix is the runtime_target prefix of an AgentCore target (D991).
const TargetPrefix = "agentcore:"

// toolSeparator splits an AgentCore tool name into target and tool.
const toolSeparator = "___"

// outputVersion is the interceptor output's version.
const outputVersion = "1.0"

// rpcMethodNotFound is JSON-RPC's "method not found".
const rpcMethodNotFound = -32601

var (
	// gatewayARN is an AgentCore gateway's ARN (D991).
	gatewayARN = regexp.MustCompile(`^arn:aws[a-z-]*:bedrock-agentcore:[a-z0-9-]+:\d{12}:gateway/[A-Za-z0-9-]{1,100}$`)
	// targetName is an AgentCore target's name (D991).
	targetName = regexp.MustCompile(`^[A-Za-z0-9-]{1,100}$`)
)

// passed are the methods that pass undecided (D994); notifications/* too.
var passed = map[string]bool{"initialize": true, "ping": true, "tools/list": true}

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves POST /runtime/agentcore.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	publicURL string
	log       *slog.Logger
}

// New returns the runtime face. publicURL is the gateway's base URL, which
// proofs are checked against.
func New(engine *dispatch.Engine, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Serves reports whether a request path is the runtime face's.
func Serves(escapedPath string) bool { return escapedPath == AgentCorePath }

// refusal is the body of a request refused before any answer for AgentCore
// (the interceptor answers it with a deny).
type refusal struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

func refuse(w http.ResponseWriter, status int, code, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, refusal{Code: code, Reason: reason}, json.Deterministic(true))
}

func output(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}

// event is the interceptor event the face reads.
type event struct {
	MCP *struct {
		GatewayRequest struct {
			Body jsontext.Value `json:"body"`
		} `json:"gatewayRequest"`
	} `json:"mcp"`
	HTTP jsontext.Value `json:"http"`
}

// rpcRequest is the JSON-RPC request in the event.
type rpcRequest struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id"`
	Method  string         `json:"method"`
	Params  jsontext.Value `json:"params"`
}

// callParams are tools/call's params.
type callParams struct {
	Name      string         `json:"name"`
	Arguments jsontext.Value `json:"arguments"`
}

// ServeHTTP serves one event.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		refuse(w, http.StatusMethodNotAllowed, "method_not_allowed", "the runtime endpoint takes POST only")
		return
	}
	if r.Header.Get("Origin") != "" {
		// An interceptor is never a browser.
		refuse(w, http.StatusForbidden, "origin_not_allowed", "browsers may not call the runtime endpoint")
		return
	}
	cfg := h.config.Current()
	if cfg == nil {
		refuse(w, http.StatusServiceUnavailable, "not_configured", "the gateway has no configuration yet")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w, http.StatusRequestEntityTooLarge, "request_too_large", "the event is larger than 1 MiB")
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
		refuse(w, http.StatusBadRequest, "run_required", "the "+dispatch.HeaderRunID+" header is required")
		return
	}
	arn := r.Header.Get(HeaderGateway)
	if !gatewayARN.MatchString(arn) {
		refuse(w, http.StatusBadRequest, CodeGatewayARNInvalid, "the "+HeaderGateway+" header must be an AgentCore gateway ARN")
		return
	}
	var ev event
	if !jsontext.Value(body).IsValid() || json.Unmarshal(body, &ev) != nil {
		refuse(w, http.StatusBadRequest, CodeEventInvalid, "the body must be an AgentCore interceptor event")
		return
	}
	if len(ev.HTTP) > 0 && ev.MCP == nil {
		refuse(w, http.StatusUnprocessableEntity, CodeHTTPNotSupported, "PantherClaw decides MCP targets' tool calls only")
		return
	}
	if ev.MCP == nil || ev.MCP.GatewayRequest.Body.Kind() != '{' {
		refuse(w, http.StatusBadRequest, CodeEventInvalid, "the event carries no MCP JSON-RPC request")
		return
	}
	original := ev.MCP.GatewayRequest.Body
	var req rpcRequest
	if json.Unmarshal(original, &req) != nil || req.Method == "" {
		refuse(w, http.StatusBadRequest, CodeEventInvalid, "the event's MCP request is not a JSON-RPC request")
		return
	}
	id := rpcID(req.ID)
	// Calls which do not enter Dispatch still need the Authority to verify
	// the workload, its proof and the named run before anything can pass.
	if req.Method != "tools/call" && !h.verifyUndecided(w, r, in) {
		return
	}
	switch {
	case passed[req.Method] || strings.HasPrefix(req.Method, "notifications/"):
		output(w, passOutput(original))
		return
	case req.Method != "tools/call":
		output(w, rpcErrorOutput(id, CodeMethodNotDecided+": PantherClaw does not decide "+req.Method+", so it does not run"))
		return
	}
	var p callParams
	if req.Params.Kind() != '{' || json.Unmarshal(req.Params, &p) != nil {
		if !h.verifyUndecided(w, r, in) {
			return
		}
		output(w, denyOutput(id, "PantherClaw cannot decide this call: its params are not a tools/call's"))
		return
	}
	target, tool, ok := strings.Cut(p.Name, toolSeparator)
	if !ok || !targetName.MatchString(target) || tool == "" {
		if !h.verifyUndecided(w, r, in) {
			return
		}
		output(w, denyOutput(id, CodeTargetUnknown+": PantherClaw cannot decide this call: the tool name names no AgentCore target"))
		return
	}
	conn := byRuntimeTarget(cfg, TargetPrefix+arn+"/"+target)
	if conn == nil {
		if !h.verifyUndecided(w, r, in) {
			return
		}
		output(w, denyOutput(id, CodeTargetUnknown+": PantherClaw cannot decide this call: no connection is bound to its AgentCore target"))
		return
	}
	args := p.Arguments
	if len(args) == 0 || args.Kind() == 'n' {
		args = jsontext.Value("{}")
	}
	action := in.Action
	if action == "" {
		action = ids.NewV7().String()
	}
	parsed, err := conn.Mapper.Runtime(r.Context(), mapping.Context{
		Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}, tool, args)
	if err != nil {
		if !h.verifyUndecided(w, r, in) {
			return
		}
		why := "its arguments do not match the reviewed mapping of " + tool
		if errors.Is(err, mapping.ErrUnmapped) {
			why = "the connection's reviewed package does not map " + tool
		}
		output(w, denyOutput(id, "PantherClaw cannot decide this call: "+why+"."))
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
	if slices.Contains(res.Reasons, reasonRunNotActive) {
		// The interceptor starts a new run (D995); AgentCore never sees it.
		w.Header().Set(HeaderRunEnded, "1")
	}
	h.log.InfoContext(r.Context(), "runtime.decided", "connection", conn.GetName(), "class", string(res.Class), "code", res.Code,
		"transaction", res.TransactionID)
	switch {
	case res.Class == "" && res.Outcome != 0:
		// Recorded as delegated (HR-760): the AgentCore gateway runs it.
		output(w, passOutput(original))
	case res.Class == dispatch.Held:
		output(w, denyOutput(id, HeldText+txn(res.TransactionID)))
	case res.SafeDetail != "":
		// The Authority's agent-safe sentence (D994a: RUNTIME_ACCOUNT_MISMATCH).
		output(w, denyOutput(id, res.SafeDetail+txn(res.TransactionID)))
	default:
		reason := "PantherClaw denied this call: " + string(res.Class)
		if res.Code != "" {
			reason += " (" + res.Code + ")"
		}
		output(w, denyOutput(id, reason+"."+txn(res.TransactionID)))
	}
}

// verifyUndecided authenticates requests that will not reach Dispatch.
func (h *Handler) verifyUndecided(w http.ResponseWriter, r *http.Request, in dispatch.Inbound) bool {
	verified, err := h.engine.Verify(r.Context(), in.Creds, in.Run)
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, "authority_unavailable", "the Authority cannot verify the workload now")
		return false
	}
	if !verified.OK {
		if verified.Code == pap.CodeRunMismatch {
			w.Header().Set(HeaderRunEnded, "1")
		}
		h.refusePAP(w, r, verified.Code, verified.Nonce)
		return false
	}
	if verified.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, verified.Nonce)
	}
	return true
}

func txn(id string) string {
	if id == "" {
		return ""
	}
	return " Transaction " + id + "."
}

// byRuntimeTarget is the kind-mcp connection this gateway serves that is
// bound to target, or nil (HR-765). Uniqueness per org is the server's
// (D991's unique index); two bound connections are none.
func byRuntimeTarget(cfg *control.Config, target string) *control.Connection {
	var found *control.Connection
	for _, c := range cfg.ByID {
		if c == nil || c.Mapper == nil || c.GetKind() != "mcp" || c.GetRuntimeTarget() != target {
			continue
		}
		if found != nil {
			return nil
		}
		found = c
	}
	return found
}

// rpcID is a JSON-RPC id (a string or a number), or null.
func rpcID(v jsontext.Value) jsontext.Value {
	switch v.Kind() {
	case '"', '0':
		return v
	}
	return jsontext.Value("null")
}

// passOutput lets the original request through to the target.
func passOutput(original jsontext.Value) []byte {
	type req struct {
		Body jsontext.Value `json:"body"`
	}
	type mcp struct {
		TransformedGatewayRequest req `json:"transformedGatewayRequest"`
	}
	b, _ := json.Marshal(struct {
		Version string `json:"interceptorOutputVersion"`
		MCP     mcp    `json:"mcp"`
	}{outputVersion, mcp{req{original}}})
	return b
}

// respond answers the MCP request without reaching the target.
func respond(body any) []byte {
	type res struct {
		StatusCode int `json:"statusCode"`
		Body       any `json:"body"`
	}
	type mcp struct {
		TransformedGatewayResponse res `json:"transformedGatewayResponse"`
	}
	b, _ := json.Marshal(struct {
		Version string `json:"interceptorOutputVersion"`
		MCP     mcp    `json:"mcp"`
	}{outputVersion, mcp{res{StatusCode: http.StatusOK, Body: body}}})
	return b
}

// denyOutput answers the call with a tool error carrying an agent-safe
// reason (D994).
func denyOutput(id jsontext.Value, text string) []byte {
	type content struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type result struct {
		IsError bool      `json:"isError"`
		Content []content `json:"content"`
	}
	return respond(struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id"`
		Result  result         `json:"result"`
	}{"2.0", id, result{IsError: true, Content: []content{{Type: "text", Text: text}}}})
}

// rpcErrorOutput answers a refused method with JSON-RPC error -32601.
func rpcErrorOutput(id jsontext.Value, message string) []byte {
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	return respond(struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id"`
		Error   rpcErr         `json:"error"`
	}{"2.0", id, rpcErr{Code: rpcMethodNotFound, Message: message}})
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
	refuse(w, http.StatusUnauthorized, string(code), "PAP/1: "+string(code))
}
