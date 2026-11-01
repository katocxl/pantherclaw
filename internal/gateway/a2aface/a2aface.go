// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package a2aface is the gateway's A2A face (G0 M14 D31, HR-323): an agent
// calls a peer agent through /a2a/{connection}, and the gateway decides
// every call under the agent's grant and rebuilds the request it sends.
//
//   - GET /a2a/{connection}/.well-known/agent-card.json serves the pinned
//     card, its interface rewritten to the gateway's (and only the allowed
//     skills, without the peer's signatures or security schemes), signed by
//     the server when it can be and otherwise unsigned (G0 M24 D232).
//   - POST /a2a/{connection} speaks the JSON-RPC 2.0 binding; the paths
//     below it (/message:send, /tasks/{id}, …) the HTTP+JSON binding. The
//     gateway calls the peer over the binding the connection pins.
//
// Every request carries PAP/1 credentials and the Authority verifies them.
// Push notification configurations and the extended card are never
// relayed (PUSH_NOT_SUPPORTED). A message carries text parts only; a task
// or context id is accepted only when the peer answered it to this run
// through this connection; everything else in a message is rebuilt, never
// passed on. The peer's answers are untrusted data (HR-327).
package a2aface

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// Limits.
const (
	// MaxBody is the largest request body read.
	MaxBody = 256 << 10
	// maxDepth bounds JSON nesting in a request (HR-100).
	maxDepth = 32
	// maxParts bounds the parts of one message.
	maxParts = 1
)

// prefix is the face's first path segment.
const prefix = "/a2a/"

// PantherClaw's error codes and reasons on this face. The JSON-RPC code is
// from the implementation-defined range; the HTTP+JSON binding answers a
// google.rpc.Status whose ErrorInfo has domain pantherclaw.dev.
const (
	codeRefused      = -32050
	codeAuthenticate = -32051
	codeUnavailable  = -32052
	codeUnknownConn  = -32053
	errorDomain      = "pantherclaw.dev"
	CodePushNot      = "PUSH_NOT_SUPPORTED"
	CodePartNot      = "A2A_PART_UNSUPPORTED"
	CodeFieldNot     = "A2A_FIELD_UNSUPPORTED"
	CodeTaskUnknown  = "A2A_TASK_UNKNOWN"
	CodeSkillNot     = "A2A_SKILL_NOT_ALLOWED"
	CodeCardDrift    = "A2A_CARD_DRIFT"
	CodeBadRequest   = "A2A_REQUEST_INVALID"
	CodeVersion      = "VERSION_NOT_SUPPORTED"
	// CodeStateFull: the gateway cannot keep the task a send may create
	// (D218).
	CodeStateFull     = "A2A_STATE_FULL"
	reasonHeld        = "PANTHERCLAW_HELD"
	reasonRefused     = "PANTHERCLAW_REFUSED"
	reasonFailed      = "PANTHERCLAW_FAILED"
	reasonAuthn       = "PANTHERCLAW_AUTHENTICATION"
	reasonUnavailable = "PANTHERCLAW_UNAVAILABLE"
)

// Peer is what the face needs of an a2a connection: the pinned card, the
// binding the gateway calls it over and the allowed skills (D30).
type Peer struct {
	Card    []byte
	Binding string
	Skills  []string
}

// PeerOf returns a connection's peer, ok false for a connection that is
// not an a2a connection with a pinned card.
type PeerOf func(conn *control.Connection) (Peer, bool)

// Configuration is the gateway's current configuration (control.Store).
type Configuration interface {
	Current() *control.Config
}

// Handler serves /a2a/{connection}.
type Handler struct {
	engine    *dispatch.Engine
	config    Configuration
	peerOf    PeerOf
	publicURL string
	origin    string
	log       *slog.Logger
	owned     ownership
	// send decides and sends one call (answer.go), relaying a stream to
	// sink; tests replace it.
	send func(ctx context.Context, c call, sink dispatch.A2ASink) dispatch.Result
	// signCard has the server sign a rewritten card; nil serves it unsigned.
	signCard SignCard
	cards    signedCards
	now      func() time.Time
}

// New returns the A2A face. publicURL is the gateway's base URL: proofs
// are checked against it, the served card points at it, and it is the
// only Origin a browser may send.
func New(engine *dispatch.Engine, config Configuration, peerOf PeerOf, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	h := &Handler{
		engine: engine, config: config, peerOf: peerOf, publicURL: strings.TrimSuffix(publicURL, "/"), log: log,
		owned: newOwned(0), now: time.Now,
	}
	h.send = h.dispatch
	if u, err := url.Parse(publicURL); err == nil {
		h.origin = u.Scheme + "://" + u.Host
	}
	return h
}

// Path returns the connection a request path names and the path below it:
// "/a2a/{connection}" and "/a2a/{connection}/…".
func Path(escapedPath string) (name, rest string, ok bool) {
	tail, found := strings.CutPrefix(escapedPath, prefix)
	if !found {
		return "", "", false
	}
	name, rest, _ = strings.Cut(tail, "/")
	if rest != "" {
		rest = "/" + rest
	}
	return name, rest, name != ""
}

// call is one A2A call as the face read it.
type call struct {
	r       *http.Request
	conn    *control.Connection
	peer    Peer
	in      dispatch.Inbound
	binding string // the binding the agent used
	method  string
	id      jsontext.Value // JSON-RPC id
	taskID  string
	// send is the rebuilt request of SendMessage and SendStreamingMessage.
	send *wire.SendMessageRequest
	// list is ListTasks' request.
	list *wire.ListTasksRequest
	// mapParams is what the package maps: the checked request params, or
	// the task or context a path and query name.
	mapParams []byte
	// release frees the place a send reserved for its task (D218);
	// nil for other methods.
	release func()
}

// createsTask reports a send that may create a task: one that names a
// task continues it, and needs no place (D221).
func (c call) createsTask() bool {
	return c.send != nil && c.send.Message.TaskID == "" &&
		(c.method == wire.MethodSendMessage || c.method == wire.MethodSendStreamingMessage)
}

// releaseSlot frees the send's reserved place, before its answer is
// recorded.
func (c call) releaseSlot() {
	if c.release != nil {
		c.release()
	}
}

func (c call) owner() owner {
	return owner{conn: c.conn.GetId(), run: c.in.Run, instance: c.in.Instance}
}

// faceError is an answer that is an error, in either binding.
type faceError struct {
	status  int    // HTTP+JSON status
	rpc     int    // JSON-RPC code
	reason  string // ErrorInfo reason
	message string
	facts   map[string]any
}

// ServeHTTP serves one request.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, rest, _ := Path(r.URL.EscapedPath())
	binding := wire.BindingHTTPJSON
	if rest == "" {
		binding = wire.BindingJSONRPC
	}
	c := call{r: r, binding: binding}
	if o := r.Header.Get("Origin"); o != "" && o != h.origin {
		h.fail(w, c, &faceError{status: http.StatusForbidden, rpc: codeRefused, reason: reasonRefused, message: "origin not allowed"})
		return
	}
	var conn *control.Connection
	if cfg := h.config.Current(); cfg != nil {
		conn = cfg.ByName[name]
	}
	peer, ok := Peer{}, false
	if conn != nil && h.peerOf != nil {
		peer, ok = h.peerOf(conn)
	}
	if !ok {
		h.fail(w, c, &faceError{status: http.StatusNotFound, rpc: codeUnknownConn, reason: reasonRefused, message: "unknown connection"})
		return
	}
	c.conn, c.peer = conn, peer
	if h.engine != nil && h.engine.A2ACardDrifted(conn) {
		// The peer's card changed since it was pinned: nothing is served or
		// sent until it is pinned again (HR-322).
		h.fail(w, c, &faceError{status: http.StatusForbidden, rpc: codeRefused, reason: CodeCardDrift, message: "the peer agent's card changed since it was pinned"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		h.fail(w, c, badRequest(http.StatusRequestEntityTooLarge, "request too large"))
		return
	}
	if rest == wire.CardPath {
		h.card(ctx, w, c, body)
		return
	}
	if v := version(r); v != "" && v != wire.Version {
		h.fail(w, c, &faceError{
			status: http.StatusBadRequest, rpc: wire.CodeVersionNotSupported, reason: CodeVersion,
			message: "A2A version not supported", facts: map[string]any{"supported": []string{wire.Version}},
		})
		return
	}
	var params jsontext.Value
	if binding == wire.BindingJSONRPC {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			h.fail(w, c, badRequest(http.StatusMethodNotAllowed, "the JSON-RPC endpoint takes POST only"))
			return
		}
		var ferr *faceError
		c.id, c.method, params, ferr = parseRPC(body)
		if ferr != nil {
			h.fail(w, c, ferr)
			return
		}
	} else {
		method, taskID, found := wire.Route(r.Method, rest)
		if !found {
			h.fail(w, c, &faceError{status: http.StatusNotFound, rpc: wire.CodeMethodNotFound, reason: CodeBadRequest, message: "no such A2A method"})
			return
		}
		c.method, c.taskID, params = method, taskID, body
	}
	if wire.Unsupported(c.method) {
		// Never relayed: a push configuration would make the peer call a
		// URL of the agent's choosing, and the extended card is the peer's
		// to show, not the gateway's (D31).
		rpc := wire.CodePushNotSupported
		if c.method == wire.MethodGetExtendedCard {
			rpc = wire.CodeUnsupportedOperation
		}
		h.fail(w, c, &faceError{status: http.StatusForbidden, rpc: rpc, reason: CodePushNot, message: "not supported through PantherClaw"})
		return
	}
	in, ok := h.inbound(ctx, w, c, body)
	if !ok {
		return
	}
	c.in = in
	if ferr := h.read(ctx, &c, params); ferr != nil {
		h.fail(w, c, ferr)
		return
	}
	if c.createsTask() {
		// A send may create a task: its place is kept before the peer sees
		// the call, so a full or unreachable store refuses it here (D218).
		// The key is this request's, since two sends may name one message
		// id and each releases only its own (D221).
		release, err := h.owned.reserve(ctx, c.owner(), ids.NewV7().String())
		if err != nil {
			h.fail(w, c, &faceError{
				status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: CodeStateFull,
				message: "the gateway cannot keep another A2A task for this caller now",
			})
			return
		}
		defer release()
		c.release = release
	}
	if wire.Streaming(c.method) {
		h.stream(ctx, w, c)
		return
	}
	h.answer(ctx, w, c, h.send(ctx, c, nil))
}

// version is the A2A version a request names (header, or query parameter).
func version(r *http.Request) string {
	if v := r.Header.Get(wire.HeaderVersion); v != "" {
		return v
	}
	return r.URL.Query().Get(wire.HeaderVersion)
}

func badRequest(status int, msg string) *faceError {
	return &faceError{status: status, rpc: wire.CodeInvalidRequest, reason: CodeBadRequest, message: msg}
}

func invalidParams(reason, msg string) *faceError {
	return &faceError{status: http.StatusBadRequest, rpc: wire.CodeInvalidParams, reason: reason, message: msg}
}

func taskUnknown() *faceError {
	// The same answer as a task that does not exist: nothing says whether
	// another run's task does.
	return &faceError{status: http.StatusNotFound, rpc: wire.CodeTaskNotFound, reason: CodeTaskUnknown, message: "task not found"}
}

// parseRPC decodes one JSON-RPC request strictly (HR-100): one object, no
// batch, no duplicate names, bounded depth, a string or number id.
func parseRPC(body []byte) (jsontext.Value, string, jsontext.Value, *faceError) {
	if t := bytes.TrimLeft(body, " \t\r\n"); len(t) > 0 && t[0] == '[' {
		return nil, "", nil, badRequest(http.StatusBadRequest, "batches are not accepted: send one request per POST")
	}
	if !jsontext.Value(body).IsValid() || depth(body) > maxDepth {
		return nil, "", nil, &faceError{status: http.StatusBadRequest, rpc: wire.CodeParse, reason: CodeBadRequest, message: "parse error"}
	}
	var req struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id,omitzero"`
		Method  string         `json:"method"`
		Params  jsontext.Value `json:"params,omitzero"`
	}
	if err := json.Unmarshal(body, &req, json.RejectUnknownMembers(true)); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		return nil, "", nil, badRequest(http.StatusBadRequest, "not a JSON-RPC 2.0 request")
	}
	if len(req.ID) == 0 || (req.ID.Kind() != '"' && req.ID.Kind() != '0') {
		return nil, "", nil, badRequest(http.StatusBadRequest, "id must be a string or a number")
	}
	if len(req.Params) > 0 && req.Params.Kind() != '{' {
		return req.ID, "", nil, invalidParams(CodeBadRequest, "params must be an object")
	}
	return req.ID, req.Method, req.Params, nil
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

// inbound reads a request's PAP/1 credentials and refuses one that cannot
// be a verified workload's, as the other faces do.
func (h *Handler) inbound(ctx context.Context, w http.ResponseWriter, c call, body []byte) (dispatch.Inbound, bool) {
	in := dispatch.ReadInbound(c.r, body, h.publicURL+c.r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(ctx, w, c, pap.CodeUseNonce, "")
	case !in.HasToken:
		code, nonce := h.engine.ReportUnknown(ctx, in.Creds, c.r.UserAgent(), "")
		h.refusePAP(ctx, w, c, code, nonce)
	case !in.SubjectOK:
		h.refusePAP(ctx, w, c, pap.CodeInvalidToken, "")
	case in.Run == "":
		h.fail(w, c, badRequest(http.StatusBadRequest, "the "+dispatch.HeaderRunID+" header is required"))
	default:
		return in, true
	}
	return in, false
}

// refusePAP answers 401 with a PAP-Error code and a nonce (PAP-1 §12).
func (h *Handler) refusePAP(ctx context.Context, w http.ResponseWriter, c call, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = h.engine.Nonce(ctx)
	}
	if nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, nonce)
	}
	w.Header().Set(dispatch.HeaderError, string(code))
	h.fail(w, c, &faceError{
		status: http.StatusUnauthorized, rpc: codeAuthenticate, reason: reasonAuthn, message: "PAP/1: " + string(code),
		facts: map[string]any{"error_class": string(dispatch.AuthenticationFailed), "error": string(code)},
	})
}

// card serves the pinned card as the agent sees it at the gateway, to a
// verified workload.
func (h *Handler) card(ctx context.Context, w http.ResponseWriter, c call, body []byte) {
	if c.r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		h.fail(w, c, badRequest(http.StatusMethodNotAllowed, "the agent card is read with GET"))
		return
	}
	in := dispatch.ReadInbound(c.r, body, h.publicURL+c.r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(ctx, w, c, pap.CodeUseNonce, "")
		return
	case !in.HasToken || !in.SubjectOK:
		h.refusePAP(ctx, w, c, pap.CodeInvalidToken, "")
		return
	}
	v, err := h.engine.Verify(ctx, in.Creds, "")
	if err != nil {
		h.log.ErrorContext(ctx, "gateway.authority_unavailable", pclog.Err(err))
		h.fail(w, c, &faceError{status: http.StatusServiceUnavailable, rpc: codeUnavailable, reason: reasonUnavailable, message: "the Authority is unavailable"})
		return
	}
	if !v.OK {
		h.refusePAP(ctx, w, c, v.Code, v.Nonce)
		return
	}
	out, err := wire.Rewrite(c.peer.Card, c.peer.Binding, h.publicURL+prefix+c.conn.GetName(), c.peer.Skills)
	if err != nil {
		h.fail(w, c, &faceError{status: http.StatusBadGateway, rpc: codeRefused, reason: reasonFailed, message: "the pinned card cannot be served"})
		return
	}
	if v.Nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, v.Nonce)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(h.signed(ctx, c.conn.GetId(), out))
}

// read decodes and checks the call's parameters, and rebuilds what the
// gateway will send (D31).
func (h *Handler) read(ctx context.Context, c *call, params jsontext.Value) *faceError {
	switch c.method {
	case wire.MethodSendMessage, wire.MethodSendStreamingMessage:
		req, ferr := h.readSend(ctx, *c, params)
		if ferr != nil {
			return ferr
		}
		c.send, c.mapParams = req, params
	case wire.MethodGetTask, wire.MethodCancelTask, wire.MethodSubscribeToTask:
		if c.binding == wire.BindingJSONRPC {
			var p struct {
				ID            string `json:"id"`
				HistoryLength *int32 `json:"historyLength,omitzero"`
			}
			if err := json.Unmarshal(params, &p, json.RejectUnknownMembers(true)); err != nil {
				return invalidParams(CodeBadRequest, "invalid params")
			}
			c.taskID = p.ID
		} else if len(bytes.TrimSpace(params)) > 0 && c.method != wire.MethodGetTask {
			var p struct {
				ID string `json:"id,omitzero"`
			}
			if err := json.Unmarshal(params, &p, json.RejectUnknownMembers(true)); err != nil || (p.ID != "" && p.ID != c.taskID) {
				return invalidParams(CodeBadRequest, "invalid params")
			}
		}
		if !wire.ValidID(c.taskID) {
			return taskUnknown()
		}
		if _, ok := h.owned.task(ctx, c.owner(), c.taskID); !ok {
			return taskUnknown()
		}
		c.mapParams, _ = json.Marshal(map[string]string{"id": c.taskID})
	case wire.MethodListTasks:
		p := wire.ListTasksRequest{}
		if c.binding == wire.BindingJSONRPC {
			if len(params) > 0 {
				if err := json.Unmarshal(params, &p, json.RejectUnknownMembers(true)); err != nil {
					return invalidParams(CodeBadRequest, "invalid params")
				}
			}
		} else {
			q := c.r.URL.Query()
			for k := range q {
				if k != "contextId" && k != "status" && k != "pageSize" && k != wire.HeaderVersion {
					return invalidParams(CodeFieldNot, "unsupported query parameter "+k)
				}
			}
			p.ContextID, p.Status = q.Get("contextId"), q.Get("status")
		}
		if p.Tenant != "" || p.PageToken != "" {
			return invalidParams(CodeFieldNot, "tenant and pageToken are not supported")
		}
		// A listing names a context this run created: no listing shows
		// another run's tasks (D31).
		if p.ContextID == "" || !h.owned.context(ctx, c.owner(), p.ContextID) {
			return taskUnknown()
		}
		c.list = &p
		c.mapParams, _ = json.Marshal(map[string]string{"contextId": p.ContextID})
	default:
		return &faceError{status: http.StatusNotFound, rpc: wire.CodeMethodNotFound, reason: CodeBadRequest, message: "Method not found: " + c.method}
	}
	return nil
}

// sendProbe finds what a send request may not carry.
type sendProbe struct {
	Tenant        string `json:"tenant"`
	Configuration struct {
		PushNotificationConfig jsontext.Value `json:"pushNotificationConfig"`
	} `json:"configuration"`
	Message struct {
		Parts []jsontext.Value `json:"parts"`
	} `json:"message"`
}

// readSend checks a SendMessage request and rebuilds it: text parts only,
// a task or context only of this run's, no push configuration, no
// extensions or references, and none of the agent's metadata (D31).
func (h *Handler) readSend(ctx context.Context, c call, params jsontext.Value) (*wire.SendMessageRequest, *faceError) {
	var probe sendProbe
	if err := json.Unmarshal(params, &probe); err != nil {
		return nil, invalidParams(CodeBadRequest, "invalid params")
	}
	if len(probe.Configuration.PushNotificationConfig) > 0 {
		return nil, &faceError{status: http.StatusForbidden, rpc: wire.CodePushNotSupported, reason: CodePushNot, message: "push notifications are not supported through PantherClaw"}
	}
	if len(probe.Message.Parts) == 0 || len(probe.Message.Parts) > maxParts {
		return nil, invalidParams(CodePartNot, "a message is one text part")
	}
	for _, raw := range probe.Message.Parts {
		var p struct {
			Text *string `json:"text"`
		}
		var members map[string]jsontext.Value
		if json.Unmarshal(raw, &members) != nil || json.Unmarshal(raw, &p) != nil || p.Text == nil {
			return nil, invalidParams(CodePartNot, "only text parts are relayed")
		}
		for k := range members {
			if k != "text" && k != "mediaType" && k != "metadata" {
				return nil, invalidParams(CodePartNot, "only text parts are relayed")
			}
		}
	}
	var req wire.SendMessageRequest
	if err := json.Unmarshal(params, &req, json.RejectUnknownMembers(true)); err != nil {
		return nil, invalidParams(CodeFieldNot, "the request carries a field PantherClaw does not relay")
	}
	m := req.Message
	switch {
	case probe.Tenant != "":
		return nil, invalidParams(CodeFieldNot, "tenant is set by the gateway")
	case m.Role != wire.RoleUser:
		return nil, invalidParams(CodeBadRequest, "the message role must be ROLE_USER")
	case !wire.ValidID(m.MessageID):
		return nil, invalidParams(CodeBadRequest, "messageId is required")
	case len(m.Extensions) > 0 || len(m.ReferenceTaskIDs) > 0:
		return nil, invalidParams(CodeFieldNot, "extensions and referenceTaskIds are not relayed")
	}
	if skill, _ := m.Metadata["skill"].(string); !slices.Contains(allowedSkills(c.peer), skill) {
		// Only the skills the connection allows (D30), whatever a grant says;
		// with none listed, the pinned card's own (D96 L6).
		return nil, &faceError{status: http.StatusForbidden, rpc: codeRefused, reason: CodeSkillNot, message: "the connection does not allow this skill"}
	}
	w := c.owner()
	if m.TaskID != "" {
		taskContext, ok := h.owned.task(ctx, w, m.TaskID)
		if !ok || (m.ContextID != "" && m.ContextID != taskContext) {
			return nil, taskUnknown()
		}
		m.ContextID = taskContext
	} else if m.ContextID != "" && !h.owned.context(ctx, w, m.ContextID) {
		return nil, taskUnknown()
	}
	parts := make([]wire.Part, len(m.Parts))
	for i, p := range m.Parts {
		parts[i] = wire.TextPart(*p.Text)
	}
	out := &wire.SendMessageRequest{Message: wire.Message{
		MessageID: m.MessageID, ContextID: m.ContextID, TaskID: m.TaskID, Role: wire.RoleUser, Parts: parts,
	}}
	if cfg := req.Configuration; cfg != nil {
		out.Configuration = &wire.SendConfiguration{AcceptedOutputModes: cfg.AcceptedOutputModes, HistoryLength: cfg.HistoryLength, Blocking: cfg.Blocking}
	}
	return out, nil
}

// allowedSkills are the skills a message may ask for: the connection's
// list, or the pinned card's skills when it lists none.
func allowedSkills(p Peer) []string {
	if len(p.Skills) > 0 {
		return p.Skills
	}
	c, err := wire.ParseCard(p.Card)
	if err != nil {
		return nil
	}
	return c.SkillIDs()
}
