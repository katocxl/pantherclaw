// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mcp is the gateway's MCP face (G0 M6 design decision 13,
// ARCHITECTURE §9): POST /mcp/{connection} speaks MCP 2026-07-28 over
// Streamable HTTP, statelessly. The JSON-RPC handling is PantherClaw's own,
// on encoding/json/v2; there is no MCP SDK.
//
// Before a request means anything, the transport rules hold (HR-080): one
// JSON-RPC request per POST (any batch is refused); MCP-Protocol-Version,
// Mcp-Method and Mcp-Name present and equal to the body (Mcp-Name after
// decoding its base64 form); on tools/call, an Mcp-Param-{Name} header for
// exactly the arguments that the tool's reviewed schema marks x-mcp-header
// and the body carries, each equal to its argument after decoding; GET and
// DELETE are 405; a foreign Origin is 403. Every request carries PAP/1
// credentials and the Authority verifies them: tools/call through
// Authorize, everything else through VerifyWorkload (HR-021). Clients see
// exactly the connection's reviewed package tools, with their reviewed
// descriptions and schemas (HR-081), and every answer is private.
// tools/call goes down the one dispatch path; a held call becomes a task
// for a client that supports the tasks extension, and an identical call
// reuses the held action (HR-185, holds.go).
package mcp

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/mcpheader"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// ProtocolVersion is the MCP revision this face speaks.
const ProtocolVersion = "2026-07-28"

// Limits and cache hints.
const (
	// MaxBody is the largest request body read.
	MaxBody = 256 << 10
	// maxDepth bounds JSON nesting in a request (HR-100).
	maxDepth = 32
	// listTTL is the ttlMs hint on lists and discovery.
	listTTL = 60_000
)

// Request headers (MCP 2026-07-28, Streamable HTTP: Request Metadata).
const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderMethod          = "Mcp-Method"
	HeaderName            = "Mcp-Name"
)

// _meta keys.
const (
	metaVersion    = "io.modelcontextprotocol/protocolVersion"
	metaServerInfo = "io.modelcontextprotocol/serverInfo"
	// PantherClaw's facts about a tool call.
	metaResult = "io.pantherclaw/result"
	metaError  = "io.pantherclaw/error"
	metaHold   = "io.pantherclaw/hold"
)

// JSON-RPC error codes: the standard ones, MCP's (-32020 to -32099) and
// PantherClaw's own, from the implementation-defined range.
const (
	codeParse              = -32700
	codeInvalidRequest     = -32600
	codeMethodNotFound     = -32601
	codeInvalidParams      = -32602
	codeHeaderMismatch     = -32020
	codeMissingCapability  = -32021
	codeUnsupportedVersion = -32022
	codeUnknownConnection  = -32001
	codeAuthentication     = -32002
	codeUnavailable        = -32003
	codeForbidden          = -32004
)

// holdRetryAfter is the retry hint on a held call until wait handles exist
// (M5 part 2).
const holdRetryAfter = 5

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves POST /mcp/{connection}.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	publicURL string
	origin    string
	log       *slog.Logger
	holds     holdStore
	sessions  sessionStore
}

// New returns the MCP face. publicURL is the gateway's base URL: proofs
// are checked against it, and it is the only Origin a browser may send.
func New(engine *dispatch.Engine, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	h := &Handler{
		engine: engine, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log,
		holds: newStore(time.Now), sessions: newSessions(time.Now),
	}
	if u, err := url.Parse(publicURL); err == nil {
		h.origin = u.Scheme + "://" + u.Host
	}
	return h
}

// Path returns the connection a request path names: "/mcp/{connection}".
func Path(escapedPath string) (string, bool) {
	name, ok := strings.CutPrefix(escapedPath, "/mcp/")
	return name, ok && name != "" && !strings.Contains(name, "/")
}

type request struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Method  string         `json:"method"`
	Params  jsontext.Value `json:"params,omitzero"`
}

// params are the fields this face reads; others (extensions) are ignored.
type params struct {
	Meta      map[string]jsontext.Value `json:"_meta,omitzero"`
	Name      string                    `json:"name,omitzero"`
	URI       string                    `json:"uri,omitzero"`
	Arguments jsontext.Value            `json:"arguments,omitzero"`
	TaskID    string                    `json:"taskId,omitzero"`
	// Task marks a 2025-11-25 task-augmented tools/call.
	Task jsontext.Value `json:"task,omitzero"`
	// InputResponses and RequestState are a 2026-07-28 retry's answers to an
	// upstream server's input requests (elicitation.go).
	InputResponses jsontext.Value `json:"inputResponses,omitzero"`
	RequestState   jsontext.Value `json:"requestState,omitzero"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitzero"`
}

type response struct {
	JSONRPC string         `json:"jsonrpc"`
	ID      jsontext.Value `json:"id,omitzero"`
	Result  any            `json:"result,omitzero"`
	Error   *rpcError      `json:"error,omitzero"`
}

func write(w http.ResponseWriter, status int, r response) {
	r.JSONRPC = "2.0"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, r, json.Deterministic(true))
}

func fail(w http.ResponseWriter, status int, id jsontext.Value, code int, msg string, data any) {
	write(w, status, response{ID: id, Error: &rpcError{Code: code, Message: msg, Data: data}})
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ending := r.Method == http.MethodDelete && len(r.Header.Values(HeaderSessionID)) > 0
	if r.Method != http.MethodPost && !ending {
		// No GET stream in either version: the gateway has nothing to
		// push. DELETE only ends a 2025-11-25 session.
		w.Header().Set("Allow", http.MethodPost)
		fail(w, http.StatusMethodNotAllowed, nil, codeInvalidRequest, "the MCP endpoint takes POST only", nil)
		return
	}
	if o := r.Header.Get("Origin"); o != "" && o != h.origin {
		fail(w, http.StatusForbidden, nil, codeForbidden, "origin not allowed", nil)
		return
	}
	name, _ := Path(r.URL.EscapedPath())
	var conn *control.Connection
	if cfg := h.config.Current(); cfg != nil {
		conn = cfg.ByName[name]
	}
	if conn == nil || conn.Mapper == nil {
		fail(w, http.StatusNotFound, nil, codeUnknownConnection, "unknown connection", nil)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		fail(w, http.StatusRequestEntityTooLarge, nil, codeInvalidRequest, "request too large", nil)
		return
	}
	if ending {
		h.endSession(w, r, conn, body)
		return
	}
	if t := bytes.TrimLeft(body, " \t\r\n"); len(t) > 0 && t[0] == '[' {
		fail(w, http.StatusBadRequest, nil, codeInvalidRequest, "batches are not accepted: send one request per POST", nil)
		return
	}
	req, p, err := parse(body)
	if err != nil {
		code := codeInvalidRequest
		if errors.Is(err, errParse) {
			code = codeParse
		}
		fail(w, http.StatusBadRequest, req.ID, code, err.Error(), nil)
		return
	}
	if req.Method == "initialize" || (protocolVersion(p.Meta) == "" && r.Header.Get(HeaderProtocolVersion) == LegacyVersion) {
		// 2025-11-25: initialize, or a request in a session (legacy.go).
		h.legacy(w, r, conn, body, req, p)
		return
	}
	if msg := headerMismatch(r.Header, req, p, toolHeaders(conn, req.Method, p.Name)); msg != "" {
		fail(w, http.StatusBadRequest, req.ID, codeHeaderMismatch, "Header mismatch: "+msg, nil)
		return
	}
	if v := protocolVersion(p.Meta); v != ProtocolVersion {
		fail(w, http.StatusBadRequest, req.ID, codeUnsupportedVersion, "Unsupported protocol version",
			map[string]any{"supported": []string{ProtocolVersion, LegacyVersion}, "requested": v})
		return
	}
	if len(req.ID) == 0 {
		// A notification: none is defined over Streamable HTTP; accepted
		// and ignored.
		w.WriteHeader(http.StatusAccepted)
		return
	}
	in, ok := h.inbound(w, r, conn, body, req.ID, req.Method, p.Name)
	if !ok {
		return
	}
	switch {
	case req.Method == "tools/call":
		h.call(w, r, conn, req, p, in)
	case req.Method == "tasks/get" || req.Method == "tasks/cancel" || req.Method == "tasks/update":
		h.task(w, r, conn, req, p, in)
	case req.Method == "tools/list" || req.Method == "server/discover":
		if _, ok := h.verify(w, r, req.ID, in); !ok {
			return
		}
		if req.Method == "tools/list" {
			write(w, http.StatusOK, response{ID: req.ID, Result: listResult(conn)})
		} else {
			write(w, http.StatusOK, response{ID: req.ID, Result: discoverResult(conn)})
		}
	case isResourceMethod(req.Method) && resourceCapability(conn) != nil:
		// Reviewed resources (resources.go, G0 M15 D31).
		if req.Method == "resources/read" {
			h.readResource(w, r, conn, req, p, in, true)
			return
		}
		if _, ok := h.verify(w, r, req.ID, in); ok {
			write(w, http.StatusOK, response{ID: req.ID, Result: listResources(conn, req.Method, true)})
		}
	default:
		// Only tools and reviewed resources are served: no prompts or
		// subscriptions.
		fail(w, http.StatusNotFound, req.ID, codeMethodNotFound, "Method not found: "+req.Method, nil)
	}
}

var errParse = errors.New("parse error: the body is not one JSON object")

// parse decodes one JSON-RPC request strictly (HR-100): one object, no
// duplicate names, valid UTF-8, bounded depth.
func parse(body []byte) (request, params, error) {
	var req request
	if !jsontext.Value(body).IsValid() || depth(body) > maxDepth {
		return req, params{}, errParse
	}
	if err := json.Unmarshal(body, &req, json.RejectUnknownMembers(true)); err != nil {
		return req, params{}, errors.New("invalid request: not a JSON-RPC 2.0 request")
	}
	switch {
	case req.JSONRPC != "2.0" || req.Method == "":
		return req, params{}, errors.New("invalid request: jsonrpc must be 2.0 and method is required")
	case len(req.ID) > 0 && req.ID.Kind() != '"' && req.ID.Kind() != '0':
		return request{}, params{}, errors.New("invalid request: id must be a string or a number")
	}
	var p params
	if len(req.Params) > 0 {
		if req.Params.Kind() != '{' {
			return req, params{}, errors.New("invalid request: params must be an object")
		}
		if err := json.Unmarshal(req.Params, &p); err != nil {
			return req, params{}, errors.New("invalid request: params do not decode")
		}
	}
	return req, p, nil
}

// depth is the deepest nesting of objects and arrays in valid JSON.
func depth(b []byte) int {
	deepest, d, inString, escaped := 0, 0, false, false
	for _, c := range b {
		switch {
		case escaped:
			escaped = false
		case inString:
			switch c {
			case '\\':
				escaped = true
			case '"':
				inString = false
			}
		case c == '"':
			inString = true
		case c == '{' || c == '[':
			d++
			deepest = max(deepest, d)
		case c == '}' || c == ']':
			d--
		}
	}
	return deepest
}

// protocolVersion is a request's _meta protocol version, or "".
func protocolVersion(meta map[string]jsontext.Value) string {
	var s string
	if v, ok := meta[metaVersion]; ok && json.Unmarshal(v, &s) == nil {
		return s
	}
	return ""
}

// headerMismatch checks the request metadata headers against the body
// (HR-080) and says what is wrong, or "". declared are the x-mcp-header
// parameters of the tool a tools/call names (none for other methods).
func headerMismatch(h http.Header, req request, p params, declared []mcpheader.Param) string {
	one := func(name string) (string, string) {
		vs := h.Values(name)
		switch len(vs) {
		case 0:
			return "", name + " header is missing"
		case 1:
			return vs[0], ""
		}
		return "", name + " header is repeated"
	}
	v, msg := one(HeaderProtocolVersion)
	if msg != "" {
		return msg
	}
	if v != protocolVersion(p.Meta) {
		return HeaderProtocolVersion + " header does not match _meta " + metaVersion
	}
	m, msg := one(HeaderMethod)
	if msg != "" {
		return msg
	}
	if m != req.Method {
		return HeaderMethod + " header does not match the method"
	}
	var source string
	named := true
	switch req.Method {
	case "tools/call", "prompts/get":
		source = p.Name
	case "resources/read":
		source = p.URI
	case "tasks/get", "tasks/cancel", "tasks/update":
		// The tasks extension: Mcp-Name is the task id.
		source = p.TaskID
	default:
		named = false
	}
	if !named {
		if len(h.Values(HeaderName)) > 0 {
			return HeaderName + " header for a method that names nothing"
		}
	} else {
		n, msg := one(HeaderName)
		if msg != "" {
			return msg
		}
		if decoded, ok := mcpheader.Decode(n); !ok || decoded != source {
			return HeaderName + " header does not match the body"
		}
	}
	return mcpheader.Check(h, declared, p.Arguments)
}

// toolHeaders are the x-mcp-header parameters of the tool a tools/call
// names, as its reviewed schema declares them; none for another method or
// a tool the connection does not serve.
func toolHeaders(conn *control.Connection, method, name string) []mcpheader.Param {
	if method != "tools/call" {
		return nil
	}
	ts := tools(conn)
	i := slices.IndexFunc(ts, func(t tool) bool { return t.Name == name })
	if i < 0 {
		return nil
	}
	return headerParams(ts[i].InputSchema)
}

// headerParams are the x-mcp-header declarations of a reviewed input
// schema, which the package decoder checked: on strings, integers and
// booleans reached through properties only, unique ignoring case.
func headerParams(s *domain.Schema) []mcpheader.Param {
	var out []mcpheader.Param
	var walk func(*domain.Schema, []string)
	walk = func(s *domain.Schema, path []string) {
		if s.Header != "" && len(path) > 0 {
			out = append(out, mcpheader.Param{Name: s.Header, Path: path, Type: s.Type})
		}
		for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
			walk(s.Properties[name], append(slices.Clip(path), name))
		}
	}
	if s != nil {
		walk(s, nil)
	}
	return out
}

// inbound reads a request's PAP/1 credentials (hashing the raw body) and
// refuses a request that cannot be a verified workload's: no proof, a
// key-only proof (reported as an unknown workload, HR-148) or a token that
// names no instance. tool is the tool a tools/call names.
func (h *Handler) inbound(w http.ResponseWriter, r *http.Request, conn *control.Connection, body []byte, id jsontext.Value,
	method, tool string,
) (dispatch.Inbound, bool) {
	in := dispatch.ReadInbound(r, body, h.publicURL+r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(w, r, id, pap.CodeUseNonce, "")
	case !in.HasToken:
		route := ""
		if method == "tools/call" {
			route = toolRoute(conn, tool)
		}
		code, nonce := h.engine.ReportUnknown(r.Context(), in.Creds, r.UserAgent(), route)
		h.refusePAP(w, r, id, code, nonce)
	case !in.SubjectOK:
		h.refusePAP(w, r, id, pap.CodeInvalidToken, "")
	default:
		return in, true
	}
	return in, false
}

// refusePAP answers 401 with a PAP-Error code and a nonce (PAP-1 §12).
func (h *Handler) refusePAP(w http.ResponseWriter, r *http.Request, id jsontext.Value, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = h.engine.Nonce(r.Context())
	}
	if nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, nonce)
	}
	w.Header().Set(dispatch.HeaderError, string(code))
	fail(w, http.StatusUnauthorized, id, codeAuthentication, "PAP/1: "+string(code),
		map[string]string{"error_class": string(dispatch.AuthenticationFailed), "error": string(code)})
}

// verify asks the Authority to verify the workload of a request that
// decides nothing, and answers when it does not verify.
func (h *Handler) verify(w http.ResponseWriter, r *http.Request, id jsontext.Value, in dispatch.Inbound) (dispatch.Verified, bool) {
	return h.verifyRun(w, r, id, in, "")
}

// verifyRun is verify for a request in run. A run the instance may not use
// is left for the caller to answer (v.Code is run_mismatch).
func (h *Handler) verifyRun(w http.ResponseWriter, r *http.Request, id jsontext.Value, in dispatch.Inbound, run string) (dispatch.Verified, bool) {
	v, err := h.engine.Verify(r.Context(), in.Creds, run)
	if err != nil {
		h.log.ErrorContext(r.Context(), "gateway.authority_unavailable", pclog.Err(err))
		fail(w, http.StatusServiceUnavailable, id, codeUnavailable, "the Authority is unavailable", nil)
		return dispatch.Verified{}, false
	}
	if !v.OK {
		if v.Code != pap.CodeRunMismatch || run == "" {
			h.refusePAP(w, r, id, v.Code, v.Nonce)
		}
		return v, false
	}
	if v.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, v.Nonce)
	}
	return v, true
}

func serverInfo() map[string]any {
	return map[string]any{metaServerInfo: map[string]string{"name": "pantherclaw-gateway", "version": version.Get().Version}}
}

func discoverResult(conn *control.Connection) map[string]any {
	caps := map[string]any{
		"tools":      map[string]any{"listChanged": false},
		"extensions": map[string]any{extTasks: map[string]any{}},
	}
	if rc := resourceCapability(conn); rc != nil {
		caps["resources"] = rc
	}
	return map[string]any{
		"resultType": "complete", "supportedVersions": []string{ProtocolVersion},
		"capabilities": caps,
		"instructions": "PantherClaw authorizes every tool call before it runs. A refused call is a tool error " +
			"whose _meta io.pantherclaw/error says why; a held call carries io.pantherclaw/hold, or becomes a task " +
			"when the client supports tasks.",
		"ttlMs": listTTL, "cacheScope": "private", "_meta": serverInfo(),
	}
}

// tool is one tool as clients see it: the reviewed description and input
// schema from the package, never anything from a target (HR-081).
type tool struct {
	Name        string         `json:"name"`
	Title       string         `json:"title,omitzero"`
	Description string         `json:"description"`
	InputSchema *domain.Schema `json:"inputSchema"`
	// Execution says, in 2025-11-25, that a call may be task-augmented.
	Execution map[string]string `json:"execution,omitzero"`
}

// dispatches reports whether a connection of this kind can run a
// definition (as the Authority checks): HTTP and MCP connections need a
// dispatch template of their kind.
func dispatches(kind string, d *domain.Definition) bool {
	switch kind {
	case "http":
		return d.Dispatch != nil && d.Dispatch.HTTP != nil
	case "mcp", "mcp_container":
		return d.Dispatch != nil && d.Dispatch.MCP != nil
	}
	return native(kind, d)
}

// tools are the connection's reviewed MCP tools, by name. A mapping
// without a reviewed input schema is not served.
func tools(conn *control.Connection) []tool {
	var out []tool
	for i := range conn.Package.Definitions {
		d := &conn.Package.Definitions[i]
		if !dispatches(conn.GetKind(), d) {
			continue
		}
		for _, m := range d.Mappings {
			if m.Channel == domain.ChannelMCP && m.InputSchema != nil {
				out = append(out, tool{Name: m.Tool, Title: d.Summary, Description: m.Description, InputSchema: m.InputSchema})
			}
		}
	}
	slices.SortFunc(out, func(a, b tool) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func toolRoute(conn *control.Connection, name string) string {
	for i := range conn.Package.Definitions {
		for _, m := range conn.Package.Definitions[i].Mappings {
			if m.Channel == domain.ChannelMCP && m.Tool == name {
				return m.Route
			}
		}
	}
	return ""
}

func listResult(conn *control.Connection) map[string]any {
	ts := tools(conn)
	if ts == nil {
		ts = []tool{}
	}
	return map[string]any{"resultType": "complete", "tools": ts, "ttlMs": listTTL, "cacheScope": "private", "_meta": serverInfo()}
}

// call serves a 2026-07-28 tools/call: a held call becomes a task when the
// client declares the tasks extension.
func (h *Handler) call(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound) {
	c, ok := h.callTool(w, r, conn, req, p, in)
	if !ok {
		return
	}
	if out, relayed := h.relay(r.Context(), conn, p.Name, c); relayed {
		write(w, http.StatusOK, response{ID: req.ID, Result: out})
		return
	}
	if c.res.Class == dispatch.Held && supportsTasks(p.Meta) {
		if t := h.holds.newTask(c.b, c.action, c.key, c.res, c.result); t != nil {
			write(w, http.StatusOK, response{ID: req.ID, Result: t.view("task", c.res.TransactionID)})
			return
		}
	}
	write(w, http.StatusOK, response{ID: req.ID, Result: c.result})
}

// called is a tools/call after the dispatch path: the answer, the tool
// result for it and, when the arguments mapped, the action decided.
type called struct {
	res    dispatch.Result
	result toolResult
	action actionir.Parsed
	key    key
	b      binding
}

// callTool maps a tools/call through the connection's package and sends it
// down the dispatch path. An unknown tool is a protocol error; everything
// PantherClaw refuses is a tool error, so the model sees why. ok is false
// when it already answered: an unknown tool, no run, or a workload that
// did not verify.
func (h *Handler) callTool(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound) (called, bool) {
	ctx := r.Context()
	if !slices.ContainsFunc(tools(conn), func(t tool) bool { return t.Name == p.Name }) {
		fail(w, http.StatusOK, req.ID, codeInvalidParams, "Unknown tool: "+p.Name, nil)
		return called{}, false
	}
	if in.Run == "" {
		fail(w, http.StatusOK, req.ID, codeInvalidParams, "the "+dispatch.HeaderRunID+" header is required", nil)
		return called{}, false
	}
	c := called{b: binding{conn: conn.GetId(), run: in.Run, instance: in.Instance}}
	// The action id is the client's (PC-Action-Id), or the held one for an
	// identical call (HR-185), or new.
	action := in.Action
	fresh := action == ""
	if fresh {
		action = ids.NewV7().String()
	}
	args := p.Arguments
	if len(args) == 0 {
		args = jsontext.Value("{}")
	}
	tc := mapping.Context{
		Org: h.config.Current().Org, Env: in.Env, RunID: in.Run, ActionID: action, AgentInstance: in.Instance, Connection: conn.GetId(),
	}
	var parsed actionir.Parsed
	var err error
	if len(p.InputResponses) > 0 {
		// A retry answering the server's input requests: a new action whose
		// answers are declared params, checked before anything is decided
		// (G0 M15 D33, HR-420). Its requestState is the handle the gateway
		// gave out, which resolves, once, to what the server sent (D39).
		stored, aerr := h.claimElicitation(c.b, p.Name, p.RequestState)
		var vals domain.Values
		var ir dispatch.InputResponses
		if aerr == nil {
			vals, ir, aerr = answers(conn.Mapper.Elicitation(p.Name), p.InputResponses, stored)
		}
		if aerr != nil {
			c.res = dispatch.Result{Class: dispatch.CannotAuthorize, Code: "invalid_input_responses"}
			c.result = errorResult(c.res, "The input responses do not answer the tool's reviewed elicitation fields.")
			return c, true
		}
		parsed, err = conn.Mapper.MCPAnswered(ctx, tc, p.Name, args, vals)
		ctx = dispatch.WithInputResponses(ctx, ir)
	} else {
		parsed, err = conn.Mapper.MCP(ctx, tc, p.Name, args)
	}
	k := actionKey(parsed.Action)
	if err == nil && fresh {
		if held, ok := h.holds.heldAction(k, c.b); ok {
			parsed.Action.ActionID, action = held, held
			parsed, err = actionir.Encode(parsed.Action)
		}
	}
	if err != nil {
		c.res = dispatch.Result{Class: dispatch.CannotAuthorize, Code: "invalid_arguments"}
		c.result = errorResult(c.res, "The arguments do not match the tool's reviewed input schema.")
		return c, true
	}
	res := h.engine.Dispatch(ctx, dispatch.Call{Connection: conn, Action: parsed, Workload: in.Creds})
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, req.ID, res.PAPError, res.Nonce)
		return called{}, false
	}
	h.holds.settle(k, c.b, action, res)
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	c.res, c.result, c.action, c.key = res, callResult(res), parsed, k
	return c, true
}

// task serves tasks/get, tasks/cancel and tasks/update (the tasks
// extension) for the run, instance and connection that created the task;
// any other binding gets "task not found" (HR-185). A poll of a working
// task resubmits its action with the poll's credentials; every other
// request is verified first (HR-021).
func (h *Handler) task(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, p params, in dispatch.Inbound) {
	if !supportsTasks(p.Meta) {
		fail(w, http.StatusBadRequest, req.ID, codeMissingCapability, "Missing required client capability",
			map[string]any{"requiredCapabilities": map[string]any{"extensions": map[string]any{extTasks: map[string]any{}}}})
		return
	}
	b := binding{conn: conn.GetId(), run: in.Run, instance: in.Instance}
	if req.Method == "tasks/get" {
		if t, claimed, _ := h.holds.lookup(p.TaskID, b, true); claimed {
			if done, res, ok := h.resubmit(w, r, conn, req, t, in); ok {
				write(w, http.StatusOK, response{ID: req.ID, Result: done.view("complete", res.TransactionID)})
			}
			return
		}
	}
	v, ok := h.verify(w, r, req.ID, in)
	if !ok {
		return
	}
	if v.Instance != in.Instance {
		// The token names another instance than the one verified: nothing
		// of either is shown.
		b = binding{}
	}
	notFound := func() {
		fail(w, http.StatusOK, req.ID, codeInvalidParams, "Failed to retrieve task: Task not found", nil)
	}
	switch req.Method {
	case "tasks/get":
		t, _, found := h.holds.lookup(p.TaskID, b, false)
		if !found {
			notFound()
			return
		}
		write(w, http.StatusOK, response{ID: req.ID, Result: t.view("complete", "")})
	case "tasks/cancel":
		if !h.holds.cancel(p.TaskID, b) {
			notFound()
			return
		}
		write(w, http.StatusOK, response{ID: req.ID, Result: map[string]any{"resultType": "complete"}})
	default: // tasks/update: no task of this face ever waits for input.
		if _, _, found := h.holds.lookup(p.TaskID, b, false); !found {
			notFound()
			return
		}
		write(w, http.StatusOK, response{ID: req.ID, Result: map[string]any{"resultType": "complete"}})
	}
}

// resubmit sends a working task's action down the dispatch path again
// with the poll's own credentials, as the workload's resubmission (PAP-1
// §8): the Authority runs the whole pipeline, and the task completes with
// the tool's result once the action is no longer held. It returns the task
// after the answer; ok is false when it already answered (the workload did
// not verify).
func (h *Handler) resubmit(w http.ResponseWriter, r *http.Request, conn *control.Connection, req request, t task,
	in dispatch.Inbound,
) (task, dispatch.Result, bool) {
	defer h.holds.release(t.id, t.binding)
	res := h.engine.Dispatch(r.Context(), dispatch.Call{Connection: conn, Action: t.action, Workload: in.Creds})
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, req.ID, res.PAPError, res.Nonce)
		return task{}, res, false
	}
	h.holds.settle(t.key, t.binding, t.action.Action.ActionID, res)
	if res.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, res.Nonce)
	}
	return h.holds.finish(t, res, callResult(res)), res, true
}

type content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolResult is a CallToolResult; resultType is 2026-07-28's and is left
// out in 2025-11-25.
type toolResult struct {
	ResultType string `json:"resultType,omitzero"`
	// Content is []content, or an upstream server's content array as it
	// sent it.
	Content           any            `json:"content"`
	StructuredContent jsontext.Value `json:"structuredContent,omitzero"`
	IsError           bool           `json:"isError"`
	Meta              map[string]any `json:"_meta"`
}

func decision(res dispatch.Result) string {
	return strings.TrimPrefix(res.Decision.String(), "DECISION_")
}

func outcome(res dispatch.Result) string {
	if res.Outcome == 0 {
		return ""
	}
	return strings.TrimPrefix(res.Outcome.String(), "OUTCOME_")
}

func mode(res dispatch.Result) string {
	if res.Monitor {
		return "monitor"
	}
	return "enforce"
}

// callResult is the tool result of a dispatched call: the target's answer
// (the credential removed) on success, otherwise a tool error.
func callResult(res dispatch.Result) toolResult {
	if res.Class != "" || res.Response == nil {
		return errorResult(res, "")
	}
	out := toolResult{
		ResultType: "complete", Content: []content{{Type: "text", Text: string(res.Response.Body)}},
		Meta: map[string]any{metaResult: map[string]any{
			"transaction_id": res.TransactionID, "outcome": outcome(res), "decision": decision(res), "mode": mode(res),
			"receipt": res.Receipt, "target_status": res.Response.Status, "truncated": res.Response.Truncated,
		}},
	}
	if res.ToolResult {
		// An upstream MCP tool's result: its content and structured content
		// pass through; its _meta is the server's and does not.
		var up struct {
			Content           jsontext.Value `json:"content"`
			StructuredContent jsontext.Value `json:"structuredContent"`
		}
		if json.Unmarshal(res.Response.Body, &up) == nil && up.Content.Kind() == '[' {
			out.Content = up.Content
			if up.StructuredContent.Kind() == '{' {
				out.StructuredContent = up.StructuredContent
			}
			return out
		}
	}
	if v := jsontext.Value(res.Response.Body); v.IsValid() && (v.Kind() == '{' || v.Kind() == '[') {
		out.StructuredContent = v
	}
	return out
}

// errorResult is a refusal or failure as a tool error, with the facts in
// _meta io.pantherclaw/error (F642) and, for a hold, io.pantherclaw/hold.
func errorResult(res dispatch.Result, detail string) toolResult {
	text := "PantherClaw did not run this call: " + string(res.Class)
	if res.Code != "" {
		text += " (" + res.Code + ")"
	}
	text += "."
	if res.TransactionID != "" {
		text += " Transaction " + res.TransactionID + "."
	}
	if detail != "" {
		text += " " + detail
	}
	facts := map[string]any{"error_class": string(res.Class), "error": res.Code, "mode": mode(res)}
	if res.Decision != 0 {
		facts["decision"] = decision(res)
	}
	if len(res.Reasons) > 0 {
		facts["reasons"] = res.Reasons
	}
	if res.TransactionID != "" {
		facts["transaction_id"] = res.TransactionID
	}
	if o := outcome(res); o != "" {
		facts["outcome"] = o
	}
	if res.Receipt != "" {
		facts["receipt"] = res.Receipt
	}
	if res.Response != nil {
		facts["target_status"] = res.Response.Status
		// An upstream server's questions reach the agent only through the
		// elicitation gate (G0 M15 D33, HR-420): an input_required answer is
		// never echoed.
		if res.Code != dispatch.CodeInputRequired {
			text += "\n\nThe target answered " + http.StatusText(res.Response.Status) + ":\n" + string(res.Response.Body)
		}
	}
	meta := map[string]any{metaError: facts}
	if res.Class == dispatch.Held {
		meta[metaHold] = map[string]any{"transaction_id": res.TransactionID, "retry_after_s": holdRetryAfter}
		text += " The call is held for approval or step-up; once it is granted, call the tool again with the same arguments."
	}
	return toolResult{ResultType: "complete", Content: []content{{Type: "text", Text: text}}, IsError: true, Meta: meta}
}
