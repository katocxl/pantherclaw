// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package a2a is a simulated A2A 1.0 agent for tests and demos
// (pantherclaw-sim a2a, G0 M14 D33). It serves an agent card (optionally
// signed) and both the JSON-RPC and the HTTP+JSON bindings: messages,
// tasks and their states, server-sent event streams, cancellation and
// subscription. Faults exercise what the gateway must survive: a card that
// changes (drift), slow streams, oversize answers, tasks that need
// authentication or fail. Like a real peer it can require a credential or
// a PantherClaw action token, so a message that bypasses the gateway is
// refused. Every answer is marked SIMULATED.
package a2a

import (
	"bufio"
	"context"
	"crypto"
	"crypto/subtle"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	wire "github.com/katocxl/pantherclaw/internal/a2a"
	"github.com/katocxl/pantherclaw/internal/sim/handshake"
)

// Paths the simulator serves below its base URL.
const (
	JSONRPCPath  = "/a2a/jsonrpc"
	RESTPath     = "/a2a/rest"
	MessagesPath = "/__sim/messages"
	maxBody      = 1 << 20
	maxTasks     = 10_000
)

// Faults configures fault injection; SetFaults replaces it at run time.
type Faults struct {
	// Latency is added to every request.
	Latency time.Duration
	// CompleteAfter keeps a new task working this long before it ends;
	// zero ends it at once.
	CompleteAfter time.Duration
	// StreamDelay is the pause between streamed events (a slow stream).
	StreamDelay time.Duration
	// OversizeBytes, when set, pads every task's artifact to this size.
	OversizeBytes int
	// AuthRequired ends every task in TASK_STATE_AUTH_REQUIRED; Fail in
	// TASK_STATE_FAILED.
	AuthRequired, Fail bool
	// Description replaces the card's description: the card drifts.
	Description string
}

// Options are fixed for the simulator's life.
type Options struct {
	// Name of the agent on its card.
	Name string
	// BaseURL is the public base its card's interfaces point at; empty
	// takes http://{Host} of each card request.
	BaseURL string
	// Skills of the card; nil takes refunds and echo.
	Skills []wire.AgentSkill
	// Token is the bearer token every call must carry (the credential
	// PantherClaw holds); empty requires none.
	Token string
	// SigningKey, when set, signs the card under KeyID.
	SigningKey crypto.Signer
	KeyID      string
	// RequireAction, when set, checks every SendMessage and
	// SendStreamingMessage request (its exact body): an error refuses it
	// (a PAP-Action or peer-run check).
	RequireAction func(r *http.Request, body []byte) error
}

// Received is one message the simulator accepted.
type Received struct {
	Method    string         `json:"method"`
	Binding   string         `json:"binding"`
	Message   wire.Message   `json:"message"`
	Metadata  map[string]any `json:"metadata,omitzero"`
	HasAction bool           `json:"has_action"`
	TaskID    string         `json:"task_id"`
}

// task is one task with when it was created.
type task struct {
	wire.Task
	created  time.Time
	canceled bool
}

// Server is the simulated agent.
type Server struct {
	opts Options
	log  *slog.Logger

	mu       sync.Mutex
	faults   Faults
	tasks    map[string]*task
	order    []string
	received []Received
	seq      int
	now      func() time.Time
}

// New returns a simulator.
func New(o Options, f Faults, log *slog.Logger) *Server {
	if o.Name == "" {
		o.Name = "Simulated peer agent"
	}
	if o.Skills == nil {
		o.Skills = []wire.AgentSkill{
			{ID: "refunds", Name: "Refunds", Description: "Asks the peer to refund a payment (SIMULATED)", Tags: []string{"payments"}},
			{ID: "echo", Name: "Echo", Description: "Echoes the message (SIMULATED)", Tags: []string{"test"}},
		}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Server{opts: o, log: log, faults: f, tasks: map[string]*task{}, now: time.Now}
}

// SetFaults replaces the faults from the next request on.
func (s *Server) SetFaults(f Faults) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.faults = f
}

func (s *Server) fault() Faults {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.faults
}

// Received returns the messages accepted so far.
func (s *Server) Received() []Received {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.received)
}

// Handler serves the simulator, with the HR-221 handshake.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+wire.CardPath, s.card)
	mux.HandleFunc("POST "+JSONRPCPath, s.jsonrpc)
	mux.HandleFunc(RESTPath+"/", s.rest)
	mux.HandleFunc("GET "+MessagesPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.MarshalWrite(w, s.Received())
	})
	return handshake.Wrap("a2a", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Simulated", "true")
		if d := s.fault().Latency; d > 0 {
			select {
			case <-time.After(d):
			case <-r.Context().Done():
				return
			}
		}
		mux.ServeHTTP(w, r)
	}))
}

// Card returns the agent card served at base.
func (s *Server) Card(base string) ([]byte, error) {
	f := s.fault()
	desc := "A simulated A2A peer agent. Everything it does is SIMULATED."
	if f.Description != "" {
		desc = f.Description
	}
	card := map[string]any{
		"name":        s.opts.Name,
		"description": desc,
		"version":     "1.0.0",
		"supportedInterfaces": []any{
			map[string]any{"url": base + JSONRPCPath, "protocolBinding": wire.BindingJSONRPC, "protocolVersion": wire.Version},
			map[string]any{"url": base + RESTPath, "protocolBinding": wire.BindingHTTPJSON, "protocolVersion": wire.Version},
		},
		"capabilities":       map[string]any{"streaming": true, "pushNotifications": false},
		"defaultInputModes":  []any{"text/plain"},
		"defaultOutputModes": []any{"text/plain"},
		"skills":             s.opts.Skills,
	}
	if s.opts.Token != "" {
		card["securitySchemes"] = map[string]any{"bearer": map[string]any{"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"}}}
		card["securityRequirements"] = []any{map[string]any{"schemes": map[string]any{"bearer": map[string]any{"list": []any{}}}}}
	}
	raw, err := json.Marshal(card, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	if s.opts.SigningKey != nil {
		return wire.Sign(raw, s.opts.KeyID, s.opts.SigningKey)
	}
	return raw, nil
}

func (s *Server) card(w http.ResponseWriter, r *http.Request) {
	base := s.opts.BaseURL
	if base == "" {
		base = "http://" + r.Host
	}
	raw, err := s.Card(base)
	if err != nil {
		http.Error(w, "card", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(raw)
}

// authorized checks the bearer token.
func (s *Server) authorized(r *http.Request) bool {
	if s.opts.Token == "" {
		return true
	}
	got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	return ok && subtle.ConstantTimeCompare([]byte(got), []byte(s.opts.Token)) == 1
}

// versionOK accepts a request for version 1.0 or one naming none.
func versionOK(r *http.Request) bool {
	v := r.Header.Get(wire.HeaderVersion)
	if v == "" {
		v = r.URL.Query().Get(wire.HeaderVersion)
	}
	return v == "" || v == wire.Version
}

// callError is an A2A error answer.
type callError struct {
	code int
	msg  string
}

func (e *callError) Error() string { return e.msg }

func errNotFound() *callError { return &callError{wire.CodeTaskNotFound, "task not found"} }

// call is one decoded call, whichever binding it came over.
type call struct {
	method  string
	binding string
	params  jsontext.Value
	taskID  string
	query   map[string]string
	body    []byte
	r       *http.Request
}

func (s *Server) jsonrpc(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body", http.StatusRequestEntityTooLarge)
		return
	}
	var req struct {
		JSONRPC string         `json:"jsonrpc"`
		ID      jsontext.Value `json:"id"`
		Method  string         `json:"method"`
		Params  jsontext.Value `json:"params"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPC(w, nil, nil, &callError{wire.CodeInvalidRequest, "invalid request"})
		return
	}
	id := req.ID
	if !versionOK(r) {
		writeRPC(w, id, nil, &callError{wire.CodeVersionNotSupported, "version not supported"})
		return
	}
	c := call{method: req.Method, binding: wire.BindingJSONRPC, params: req.Params, body: body, r: r}
	if wire.Streaming(c.method) {
		s.stream(r.Context(), w, c, func(ev wire.StreamResponse) any {
			return wire.RPCResponse{JSONRPC: "2.0", ID: id, Result: ev}
		}, func(e *callError) { writeRPC(w, id, nil, e) })
		return
	}
	res, cerr := s.do(c)
	writeRPC(w, id, res, cerr)
}

func writeRPC(w http.ResponseWriter, id jsontext.Value, result any, e *callError) {
	resp := map[string]any{"jsonrpc": "2.0"}
	if len(id) > 0 {
		resp["id"] = id
	} else {
		resp["id"] = nil
	}
	if e != nil {
		resp["error"] = wire.RPCError{Code: e.code, Message: e.msg}
	} else {
		resp["result"] = result
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.MarshalWrite(w, resp)
}

func (s *Server) rest(w http.ResponseWriter, r *http.Request) {
	if !s.authorized(r) {
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !versionOK(r) {
		writeREST(w, nil, &callError{wire.CodeVersionNotSupported, "version not supported"})
		return
	}
	method, taskID, ok := wire.Route(r.Method, strings.TrimPrefix(r.URL.Path, RESTPath))
	if !ok {
		writeREST(w, nil, &callError{wire.CodeMethodNotFound, "no such method"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		http.Error(w, "body", http.StatusRequestEntityTooLarge)
		return
	}
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			q[k] = v[0]
		}
	}
	c := call{method: method, binding: wire.BindingHTTPJSON, params: body, taskID: taskID, query: q, body: body, r: r}
	if wire.Streaming(method) {
		s.stream(r.Context(), w, c, func(ev wire.StreamResponse) any { return ev }, func(e *callError) { writeREST(w, nil, e) })
		return
	}
	res, cerr := s.do(c)
	writeREST(w, res, cerr)
}

// writeREST answers in the HTTP+JSON binding: the result, or a
// google.rpc.Status error (§11).
func writeREST(w http.ResponseWriter, result any, e *callError) {
	w.Header().Set("Content-Type", wire.ContentType)
	if e == nil {
		_ = json.MarshalWrite(w, result)
		return
	}
	status := wire.HTTPStatus(e.code)
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]any{"error": map[string]any{
		"code": status, "status": statusName(status), "message": e.msg,
		"details": []any{map[string]any{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": reason(e.code), "domain": "a2a-protocol.org"}},
	}})
}

func statusName(status int) string {
	switch status {
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusInternalServerError:
		return "INTERNAL"
	}
	return "INVALID_ARGUMENT"
}

func reason(code int) string {
	switch code {
	case wire.CodeTaskNotFound:
		return "TASK_NOT_FOUND"
	case wire.CodeTaskNotCancelable:
		return "TASK_NOT_CANCELABLE"
	case wire.CodePushNotSupported:
		return "PUSH_NOTIFICATION_NOT_SUPPORTED"
	case wire.CodeUnsupportedOperation:
		return "UNSUPPORTED_OPERATION"
	case wire.CodeVersionNotSupported:
		return "VERSION_NOT_SUPPORTED"
	}
	return "INVALID_REQUEST"
}

// do runs a call that answers once.
func (s *Server) do(c call) (any, *callError) {
	switch c.method {
	case wire.MethodSendMessage:
		t, msg, err := s.send(c)
		if err != nil {
			return nil, err
		}
		if msg != nil {
			return wire.SendMessageResponse{Message: msg}, nil
		}
		return wire.SendMessageResponse{Task: t}, nil
	case wire.MethodGetTask:
		id := c.taskID
		if c.binding == wire.BindingJSONRPC {
			var p wire.GetTaskRequest
			if json.Unmarshal(c.params, &p) != nil {
				return nil, &callError{wire.CodeInvalidParams, "invalid params"}
			}
			id = p.ID
		}
		t := s.snapshot(id)
		if t == nil {
			return nil, errNotFound()
		}
		return t, nil
	case wire.MethodListTasks:
		var p wire.ListTasksRequest
		if c.binding == wire.BindingJSONRPC {
			if len(c.params) > 0 && json.Unmarshal(c.params, &p) != nil {
				return nil, &callError{wire.CodeInvalidParams, "invalid params"}
			}
		} else {
			p.ContextID, p.Status = c.query["contextId"], c.query["status"]
			if n, err := strconv.Atoi(c.query["pageSize"]); err == nil {
				p.PageSize = int32(min(max(n, 0), 100))
			}
		}
		return s.list(p), nil
	case wire.MethodCancelTask:
		id := c.taskID
		if c.binding == wire.BindingJSONRPC {
			var p wire.TaskIDRequest
			if json.Unmarshal(c.params, &p) != nil {
				return nil, &callError{wire.CodeInvalidParams, "invalid params"}
			}
			id = p.ID
		}
		return s.cancel(id)
	case wire.MethodCreatePushConfig, wire.MethodGetPushConfig, wire.MethodListPushConfigs, wire.MethodDeletePushConfig:
		return nil, &callError{wire.CodePushNotSupported, "push notifications not supported"}
	case wire.MethodGetExtendedCard:
		return nil, &callError{wire.CodeUnsupportedOperation, "no extended card"}
	}
	return nil, &callError{wire.CodeMethodNotFound, "method not found"}
}

// send accepts a message: a new task, the next turn of one of its tasks,
// or (for the text "ping") a direct message answer.
func (s *Server) send(c call) (*wire.Task, *wire.Message, *callError) {
	var p wire.SendMessageRequest
	if err := json.Unmarshal(c.params, &p); err != nil || p.Message.MessageID == "" || p.Message.Role != wire.RoleUser || len(p.Message.Parts) == 0 {
		return nil, nil, &callError{wire.CodeInvalidParams, "invalid message"}
	}
	if s.opts.RequireAction != nil {
		if err := s.opts.RequireAction(c.r, c.body); err != nil {
			s.log.Info("sim.a2a_refused", slog.String("reason", err.Error()))
			return nil, nil, &callError{wire.CodeInvalidRequest, "refused: " + err.Error()}
		}
	}
	f := s.fault()
	s.mu.Lock()
	defer s.mu.Unlock()
	rec := Received{Method: c.method, Binding: c.binding, Message: p.Message, Metadata: p.Metadata, HasAction: c.r.Header.Get("PAP-Action") != ""}
	if p.Message.Text() == "ping" && p.Message.TaskID == "" {
		s.received = append(s.received, rec)
		reply := wire.Message{MessageID: s.next("msg"), ContextID: p.Message.ContextID, Role: wire.RoleAgent, Parts: []wire.Part{wire.TextPart("pong (SIMULATED)")}}
		return nil, &reply, nil
	}
	now := s.now()
	var t *task
	if id := p.Message.TaskID; id != "" {
		t = s.tasks[id]
		if t == nil || (p.Message.ContextID != "" && p.Message.ContextID != t.ContextID) {
			return nil, nil, errNotFound()
		}
		if wire.Terminal(s.state(t, f, now)) {
			return nil, nil, &callError{wire.CodeUnsupportedOperation, "task is in a terminal state"}
		}
		t.created = now
	} else {
		if len(s.tasks) >= maxTasks {
			return nil, nil, &callError{wire.CodeInternal, "too many tasks"}
		}
		ctxID := p.Message.ContextID
		if ctxID == "" {
			ctxID = s.next("ctx")
		}
		t = &task{Task: wire.Task{ID: s.next("task"), ContextID: ctxID}, created: now}
		s.tasks[t.ID] = t
		s.order = append(s.order, t.ID)
	}
	msg := p.Message
	msg.TaskID, msg.ContextID = t.ID, t.ContextID
	t.History = append(t.History, msg)
	rec.TaskID = t.ID
	s.received = append(s.received, rec)
	snap := s.view(t, f, now)
	return &snap, nil, nil
}

func (s *Server) next(prefix string) string {
	s.seq++
	return fmt.Sprintf("%s-%d", prefix, s.seq)
}

// state is a task's state at now.
func (s *Server) state(t *task, f Faults, now time.Time) string {
	switch {
	case t.canceled:
		return wire.StateCanceled
	case f.CompleteAfter > 0 && now.Before(t.created.Add(f.CompleteAfter)):
		return wire.StateWorking
	case f.AuthRequired:
		return wire.StateAuthRequired
	case f.Fail:
		return wire.StateFailed
	}
	return wire.StateCompleted
}

// view is a task as answered at now (callers hold mu).
func (s *Server) view(t *task, f Faults, now time.Time) wire.Task {
	out := t.Task
	out.History = slices.Clone(t.History)
	st := s.state(t, f, now)
	out.Status = wire.TaskStatus{State: st, Timestamp: now.UTC().Format(time.RFC3339)}
	if st == wire.StateCompleted {
		out.Artifacts = []wire.Artifact{s.artifact(t, f)}
	}
	return out
}

// artifact is a completed task's answer.
func (s *Server) artifact(t *task, f Faults) wire.Artifact {
	var last string
	if n := len(t.History); n > 0 {
		last = t.History[n-1].Text()
	}
	text := "SIMULATED: done: " + last
	if f.OversizeBytes > len(text) {
		text += strings.Repeat("x", f.OversizeBytes-len(text))
	}
	return wire.Artifact{ArtifactID: t.ID + "-result", Name: "result", Parts: []wire.Part{wire.TextPart(text)}}
}

func (s *Server) snapshot(id string) *wire.Task {
	f := s.fault()
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[id]
	if t == nil {
		return nil
	}
	v := s.view(t, f, s.now())
	return &v
}

func (s *Server) list(p wire.ListTasksRequest) wire.ListTasksResponse {
	f := s.fault()
	s.mu.Lock()
	defer s.mu.Unlock()
	size := p.PageSize
	if size <= 0 || size > 100 {
		size = 50
	}
	out := wire.ListTasksResponse{Tasks: []wire.Task{}, PageSize: size}
	now := s.now()
	for i := len(s.order) - 1; i >= 0; i-- {
		t := s.tasks[s.order[i]]
		if p.ContextID != "" && t.ContextID != p.ContextID {
			continue
		}
		v := s.view(t, f, now)
		if p.Status != "" && v.Status.State != p.Status {
			continue
		}
		out.TotalSize++
		if int32(len(out.Tasks)) < size { //nolint:gosec // G115: bounded by maxTasks
			out.Tasks = append(out.Tasks, v)
		}
	}
	return out
}

func (s *Server) cancel(id string) (any, *callError) {
	f := s.fault()
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[id]
	if t == nil {
		return nil, errNotFound()
	}
	now := s.now()
	if wire.Terminal(s.state(t, f, now)) {
		return nil, &callError{wire.CodeTaskNotCancelable, "task cannot be canceled"}
	}
	t.canceled = true
	return s.view(t, f, now), nil
}

// stream answers SendStreamingMessage and SubscribeToTask with server-sent
// events: the task, its status changes, its artifact and its final status.
func (s *Server) stream(ctx context.Context, w http.ResponseWriter, c call, wrap func(wire.StreamResponse) any, fail func(*callError)) {
	var id string
	switch c.method {
	case wire.MethodSendStreamingMessage:
		t, msg, err := s.send(c)
		if err != nil {
			fail(err)
			return
		}
		if msg != nil {
			sse(w, wrap(wire.StreamResponse{Message: msg}))
			return
		}
		id = t.ID
	default:
		id = c.taskID
		if c.binding == wire.BindingJSONRPC {
			var p wire.TaskIDRequest
			if json.Unmarshal(c.params, &p) != nil {
				fail(&callError{wire.CodeInvalidParams, "invalid params"})
				return
			}
			id = p.ID
		}
		t := s.snapshot(id)
		if t == nil {
			fail(errNotFound())
			return
		}
		if wire.Terminal(t.Status.State) {
			fail(&callError{wire.CodeUnsupportedOperation, "task is in a terminal state"})
			return
		}
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	t := s.snapshot(id)
	if t == nil {
		return
	}
	submitted := *t
	submitted.Status = wire.TaskStatus{State: wire.StateSubmitted, Timestamp: t.Status.Timestamp}
	submitted.Artifacts = nil
	if !s.emit(ctx, w, wrap(wire.StreamResponse{Task: &submitted})) {
		return
	}
	if !s.emit(ctx, w, wrap(wire.StreamResponse{StatusUpdate: &wire.TaskStatusUpdateEvent{TaskID: id, ContextID: t.ContextID, Status: wire.TaskStatus{State: wire.StateWorking}}})) {
		return
	}
	for {
		t = s.snapshot(id)
		if t == nil {
			return
		}
		if t.Status.State != wire.StateWorking {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(25 * time.Millisecond):
		}
	}
	for _, a := range t.Artifacts {
		if !s.emit(ctx, w, wrap(wire.StreamResponse{ArtifactUpdate: &wire.TaskArtifactUpdateEvent{TaskID: id, ContextID: t.ContextID, Artifact: a, LastChunk: true}})) {
			return
		}
	}
	s.emit(ctx, w, wrap(wire.StreamResponse{StatusUpdate: &wire.TaskStatusUpdateEvent{TaskID: id, ContextID: t.ContextID, Status: t.Status}}))
}

// emit writes one event after the stream delay; false once the client is
// gone.
func (s *Server) emit(ctx context.Context, w http.ResponseWriter, v any) bool {
	if d := s.fault().StreamDelay; d > 0 {
		select {
		case <-ctx.Done():
			return false
		case <-time.After(d):
		}
	}
	return sse(w, v)
}

func sse(w http.ResponseWriter, v any) bool {
	b, err := json.Marshal(v)
	if err != nil {
		return false
	}
	bw := bufio.NewWriter(w)
	_, _ = bw.WriteString("data: ")
	_, _ = bw.Write(b)
	_, _ = bw.WriteString("\n\n")
	if bw.Flush() != nil {
		return false
	}
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	return true
}
