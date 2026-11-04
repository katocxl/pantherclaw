// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package modelconn is the gateway's path for model connections (G0 M29
// D812–D820; HR-690..HR-695), the written exception to HR-075 for them only
// (HR-691). The HTTP face hands it a call over a model connection before it
// reads the body. It reads at most 16 MiB, strictly parses the body with
// internal/modelapi, builds the action from the request's metadata and the
// SHA-256 of the body it will forward, and sends it down the engine's model
// path, which forwards exactly that body to the connection's base URL plus
// the operation's fixed path with only the listed headers and the held key.
// The answer is streamed back as it arrives, at most 16 MiB in 10 minutes;
// an answer cut short breaks the agent's connection rather than read as
// whole. Every refusal is in the provider's error shape, so SDKs show it.
// Nothing here logs a prompt or a reply (D820, HR-695); the reply is kept
// only for a capture profile on a connection with prompt capture on (G0 M30
// D945b).
package modelconn

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	"github.com/katocxl/pantherclaw/internal/modelapi"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
)

// MaxBody is the largest request body read (D814).
const MaxBody = modelapi.MaxBody

// DefaultMaxOutputTokens is what a request without a max-tokens field gets
// when its connection sets none (D811).
const DefaultMaxOutputTokens = 64000

// Codes of refusals made before dispatch (D812, D819).
const (
	CodeUnknownRoute         = "unknown_route"
	CodeQueryNotAllowed      = "query_not_allowed"
	CodeUnsupportedMediaType = "unsupported_media_type"
	CodeBodyTooLarge         = modelapi.CodeTooLarge
	CodeInvalidJSON          = modelapi.CodeInvalidJSON
	CodeInvalidRequest       = modelapi.CodeInvalidRequest
	CodeIDsRequired          = "run_and_action_ids_required"
)

// PantherClaw's response headers (the HTTP face's).
const (
	headerTransaction = "PC-Transaction-Id"
	headerMode        = "PC-Mode"
	headerDecision    = "PC-Decision"
)

// Handler serves calls over model connections.
type Handler struct {
	engine    *dispatch.Engine
	publicURL string
	log       *slog.Logger
}

// New returns the model path. publicURL is the base URL workloads call:
// request proofs are checked against it (PAP-1 §4).
func New(engine *dispatch.Engine, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Serves reports whether conn is a model connection, which only this path
// serves (D811).
func Serves(conn *control.Connection) bool {
	return conn != nil && conn.GetKind() == dispatch.KindModel
}

// Serve serves one call over conn, a model connection of configuration
// cfg; rest is the escaped path after the connection's name. The body is
// not read yet.
func (h *Handler) Serve(w http.ResponseWriter, r *http.Request, cfg *control.Config, conn *control.Connection, rest string) {
	// One call, its stream included, takes at most 10 minutes (D814); the
	// server's own deadlines are for every other route.
	ctx, cancel := context.WithTimeout(r.Context(), dispatch.ModelConnTimeout)
	defer cancel()
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(dispatch.ModelConnTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(dispatch.ModelConnTimeout + time.Minute))
	api := apiOf(conn)
	rt, ok := match(conn, r.Method, rest)
	if !ok {
		refuse(w, api, http.StatusNotFound, "not_found_error", fail(CodeUnknownRoute))
		return
	}
	query, ok := allowedQuery(rt.api, r.URL.RawQuery)
	if !ok {
		refuse(w, api, http.StatusBadRequest, "invalid_request_error", fail(CodeQueryNotAllowed))
		return
	}
	if !rt.api.Read() {
		if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
			refuse(w, api, http.StatusUnsupportedMediaType, "invalid_request_error", fail(CodeUnsupportedMediaType))
			return
		}
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w, api, http.StatusRequestEntityTooLarge, "request_too_large", fail(CodeBodyTooLarge))
		return
	}
	if rt.api.Read() && len(body) > 0 {
		refuse(w, api, http.StatusBadRequest, "invalid_request_error", fail(CodeInvalidRequest))
		return
	}
	in := dispatch.ReadInbound(r, body, h.publicURL+r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(w, r, api, pap.CodeUseNonce, "")
		return
	case !in.HasToken:
		code, nonce := h.engine.ReportUnknown(ctx, in.Creds, r.UserAgent(), rt.route)
		h.refusePAP(w, r, api, code, nonce)
		return
	case !in.SubjectOK:
		h.refusePAP(w, r, api, pap.CodeInvalidToken, "")
		return
	case in.Run == "" || in.Action == "":
		refuse(w, api, http.StatusBadRequest, "invalid_request_error", fail(CodeIDsRequired))
		return
	}
	if res, ok := h.engine.ModelAdmit(ctx, conn); !ok {
		h.refuseResult(w, r, api, res)
		return
	}
	var req *modelapi.Request
	if !rt.api.Read() {
		maxOut := conn.GetModel().GetMaxOutputTokens()
		if maxOut <= 0 {
			maxOut = DefaultMaxOutputTokens
		}
		if req, err = modelapi.Parse(rt.api, body, maxOut); err != nil {
			code := cmpOr(modelapi.Code(err), CodeInvalidRequest)
			if code == CodeBodyTooLarge {
				refuse(w, api, http.StatusRequestEntityTooLarge, "request_too_large", fail(code))
			} else {
				refuse(w, api, http.StatusBadRequest, "invalid_request_error", fail(code))
			}
			return
		}
	}
	action, err := buildAction(cfg, conn, rt, req, in)
	if err != nil {
		refuse(w, api, http.StatusBadRequest, "invalid_request_error", fail(CodeInvalidRequest))
		return
	}
	target, err := outboundURL(conn, rt, query)
	if err != nil {
		refuse(w, api, http.StatusNotFound, "not_found_error", fail(CodeUnknownRoute))
		return
	}
	method := http.MethodGet
	if !rt.api.Read() {
		method = http.MethodPost
	}
	st := &answerState{}
	res := h.engine.DispatchModel(ctx, dispatch.ModelCall{
		Connection: conn, Action: action, Workload: in.Creds, Request: req, Method: method, URL: target,
		Header: requestHeaders(rt.api, r.Header, req != nil), Answer: h.answer(w, rt.api, st),
	})
	if st.started {
		if st.abort {
			// A cut, broken or errored answer must not read as whole (D814,
			// D818): the agent's connection is broken.
			panic(http.ErrAbortHandler)
		}
		return
	}
	h.refuseResult(w, r, api, res)
}

// cmpOr is the first non-empty string.
func cmpOr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// route is a matched model operation.
type route struct {
	def   *defs.Definition
	api   modelapi.API
	route string
	// suffix is the operation's fixed path, and id the model a read of one
	// model names (unescaped).
	suffix, id string
}

// apiOf is the API family of conn's package, for the shape of a refusal
// before any route matched: Anthropic's when the package serves an
// Anthropic API.
func apiOf(conn *control.Connection) modelapi.API {
	if conn.Package != nil {
		for i := range conn.Package.Definitions {
			if d := &conn.Package.Definitions[i]; d.IsModel() {
				return modelapi.API(d.Dispatch.Model.API)
			}
		}
	}
	return modelapi.OpenAIChat
}

// basePath is the escaped path of conn's base URL, without a trailing
// slash.
func basePath(conn *control.Connection) (string, bool) {
	u, err := url.Parse(conn.GetBaseUrl())
	if err != nil {
		return "", false
	}
	return strings.TrimSuffix(u.EscapedPath(), "/"), true
}

// match finds the model operation a request names (D812, D813): its path
// must be the base URL's path plus the operation's path, or for a read of
// one model the models path plus one segment, the model id.
func match(conn *control.Connection, method, rest string) (route, bool) {
	base, ok := basePath(conn)
	if !ok || conn.Package == nil {
		return route{}, false
	}
	for i := range conn.Package.Definitions {
		d := &conn.Package.Definitions[i]
		if !d.IsModel() {
			continue
		}
		for _, m := range d.Mappings {
			if m.Channel != defs.ChannelHTTP || m.Method != method {
				continue
			}
			rt := route{def: d, api: modelapi.API(d.Dispatch.Model.API), route: m.Route, suffix: d.Dispatch.Model.Path}
			if prefix, isOne := strings.CutSuffix(m.Path, "/{id}"); isOne {
				esc, found := strings.CutPrefix(rest, base+prefix+"/")
				if !found || esc == "" || strings.Contains(esc, "/") {
					continue
				}
				id, err := url.PathUnescape(esc)
				if err != nil || modelapi.CheckModelID(id) != nil {
					continue
				}
				rt.id = id
				return rt, true
			}
			if rest == base+m.Path {
				return rt, true
			}
		}
	}
	return route{}, false
}

var apiVersion = regexp.MustCompile(`^[a-z0-9.-]{1,32}$`)

// allowedQuery is the query forwarded (D812): beta=true to an Anthropic
// API, api-version to an OpenAI one, nothing else; ok is false for any
// other parameter or value.
func allowedQuery(api modelapi.API, raw string) (string, bool) {
	if raw == "" {
		return "", true
	}
	q, err := url.ParseQuery(raw)
	if err != nil {
		return "", false
	}
	out := url.Values{}
	for k, vs := range q {
		if len(vs) != 1 {
			return "", false
		}
		switch {
		case api.Anthropic() && k == "beta" && vs[0] == "true":
		case !api.Anthropic() && k == "api-version" && apiVersion.MatchString(vs[0]):
		default:
			return "", false
		}
		out.Set(k, vs[0])
	}
	return out.Encode(), true
}

// outboundURL is the connection's base URL plus the operation's fixed path
// (and the model a read of one names) and the allowed query (D812).
func outboundURL(conn *control.Connection, rt route, query string) (*url.URL, error) {
	target := strings.TrimSuffix(conn.GetBaseUrl(), "/") + rt.suffix
	if rt.id != "" {
		target += "/" + url.PathEscape(rt.id)
	}
	if query != "" {
		target += "?" + query
	}
	return url.Parse(target)
}

// buildAction is the call's action (D813): target {model, <model id>}, the
// models list's target id "models" (D872), and the params its definition
// declares, from the parsed request.
func buildAction(cfg *control.Config, conn *control.Connection, rt route, req *modelapi.Request, in dispatch.Inbound) (actionir.Parsed, error) {
	d := rt.def
	vals := defs.Values{}
	put := func(name string, v defs.Value) {
		if _, ok := d.Params[name]; ok {
			vals[name] = v
		}
	}
	target := actionir.Target{Type: d.Target.Type}
	switch {
	case req != nil:
		target.ID = req.Model
		put("model", defs.Value{Type: defs.TypeIdentifier, Str: req.Model})
		if rt.api.MaxTokensField() != "" {
			put("max_tokens", defs.Value{Type: defs.TypeInteger, Int: req.MaxTokens})
		}
		if rt.api == modelapi.OpenAIChat {
			put("choices", defs.Value{Type: defs.TypeInteger, Int: req.Choices})
		}
		put("stream", defs.Value{Type: defs.TypeBoolean, Bool: req.Stream})
		put("input_bytes", defs.Value{Type: defs.TypeInteger, Int: req.InputBytes()})
		if len(req.ServerTools) > 0 {
			put("server_tools", defs.Value{Type: defs.TypeIdentifierList, List: req.ServerTools})
		}
		put("body_sha256", defs.Value{Type: defs.TypeIdentifier, Str: req.Sha256})
	case rt.id != "":
		target.ID = rt.id
		put("model", defs.Value{Type: defs.TypeIdentifier, Str: rt.id})
	default:
		target.ID = "models"
	}
	if !d.Target.MatchID(target.ID) || !d.Target.MatchAccount(target.Account) {
		return actionir.Parsed{}, actionir.ErrAmbiguous
	}
	params, err := d.EncodeParams(vals)
	if err != nil {
		return actionir.Parsed{}, err
	}
	dedupe, err := d.DedupeKey(target, vals)
	if err != nil {
		return actionir.Parsed{}, err
	}
	return actionir.Encode(actionir.ActionIR{
		V: actionir.Version, Org: cfg.Org, Env: in.Env, RunID: in.Run, ActionID: in.Action, AgentInstance: in.Instance,
		Connection: conn.GetId(), Operation: d.Operation,
		Definition: actionir.Definition{Package: conn.Package.Name, Version: conn.Package.Version, Digest: d.Digest},
		Channel:    string(defs.ChannelHTTP), Route: rt.route, Target: target, Params: params, DedupeKey: dedupe,
	})
}

var (
	anthropicVersion = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)
	betaList         = regexp.MustCompile(`^[a-z0-9-]+(, ?[a-z0-9-]+)*$`)
)

// maxBeta is the longest beta header forwarded.
const maxBeta = 512

// defaultAnthropicVersion is sent when the agent sends none that fits.
const defaultAnthropicVersion = "2023-06-01"

// requestHeaders are the only headers the provider gets besides the
// credential (D812).
func requestHeaders(api modelapi.API, in http.Header, hasBody bool) http.Header {
	h := http.Header{}
	if hasBody {
		h.Set("Content-Type", "application/json")
	}
	accept := "application/json"
	if a := in.Get("Accept"); a == "application/json" || a == "text/event-stream" {
		accept = a
	}
	h.Set("Accept", accept)
	beta := func(name string) {
		if v := in.Get(name); v != "" && len(v) <= maxBeta && betaList.MatchString(v) {
			h.Set(name, v)
		}
	}
	if api.Anthropic() {
		v := in.Get("Anthropic-Version")
		if !anthropicVersion.MatchString(v) {
			v = defaultAnthropicVersion
		}
		h.Set("Anthropic-Version", v)
		beta("Anthropic-Beta")
	} else {
		beta("OpenAI-Beta")
	}
	h.Set("User-Agent", "pantherclaw-gateway/"+version.Get().Version)
	return h
}

// answerHeaders are the provider's headers passed back (D812), besides
// those with answerPrefixes.
var answerHeaders = []string{"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id"}

var answerPrefixes = []string{"Anthropic-Ratelimit-", "X-Ratelimit-"}

// answerState is what the answer did, for Serve.
type answerState struct {
	// started: the status line went to the agent; abort: the answer is
	// incomplete and the agent's connection must break.
	started, abort bool
}

// answer returns the engine's Answer: it passes the provider's status, the
// listed headers and the body on as they are read, flushing each read,
// parses usage from the body or the event stream (D818) and never passes
// the placed key on (HR-076).
func (h *Handler) answer(w http.ResponseWriter, api modelapi.API, st *answerState) func(dispatch.ModelStart) dispatch.ModelAnswer {
	return func(s dispatch.ModelStart) dispatch.ModelAnswer {
		res := s.Response
		hdr := w.Header()
		for name, vs := range res.Header {
			name = http.CanonicalHeaderKey(name)
			if !answerHeader(name) {
				continue
			}
			for _, v := range vs {
				if len(s.Secret) == 0 || !strings.Contains(v, string(s.Secret)) {
					hdr.Add(name, v)
				}
			}
		}
		h.facts(w, s.TransactionID, s.Decision, s.Monitor, s.Nonce)
		st.started = true
		w.WriteHeader(res.StatusCode)
		mt, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
		var stream *modelapi.Stream
		if mt == "text/event-stream" {
			stream = modelapi.NewStream(api)
		}
		sum := sha256.New()
		var whole bytes.Buffer
		red := &redactor{w: w, secret: s.Secret}
		rc := http.NewResponseController(w)
		buf := make([]byte, 32<<10)
		var ans dispatch.ModelAnswer
		eof := false
		for !eof && ans.Err == nil {
			n, rerr := res.Body.Read(buf)
			if n > 0 {
				p := buf[:n]
				sum.Write(p)
				ans.Size += int64(n)
				if room := s.Keep - len(ans.Kept); room > 0 {
					ans.Kept = append(ans.Kept, p[:min(room, n)]...) // G0 M30 D945b
				}
				if stream != nil {
					_, _ = stream.Write(p)
				} else {
					whole.Write(p)
				}
				if err := red.Write(p); err != nil {
					ans.Err = err
					break
				}
				_ = rc.Flush()
			}
			switch {
			case errors.Is(rerr, io.EOF):
				eof = true
			case rerr != nil:
				ans.Err = rerr
			}
		}
		if ans.Err == nil {
			if err := red.Close(); err != nil {
				ans.Err = err
			}
			_ = rc.Flush()
		}
		ans.Digest = sum.Sum(nil)
		if ans.Err == nil {
			switch ok2xx := res.StatusCode >= 200 && res.StatusCode < 300; {
			case stream != nil:
				ans.Complete, ans.Errored, ans.Usage = stream.Complete(), stream.Errored(), stream.Usage()
			case ok2xx:
				ans.Complete = jsontext.Value(whole.Bytes()).IsValid()
				ans.Usage = modelapi.AnswerUsage(api, whole.Bytes())
			default:
				ans.Complete = true // a rejected call's whole body was read
			}
		}
		st.abort = ans.Err != nil || !ans.Complete || ans.Errored
		return ans
	}
}

func answerHeader(name string) bool {
	for _, k := range answerHeaders {
		if name == k {
			return true
		}
	}
	if strings.HasPrefix(name, "Pc-") {
		return true
	}
	for _, p := range answerPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// facts sets PantherClaw's own headers.
func (h *Handler) facts(w http.ResponseWriter, txn string, d pb.Decision, monitor bool, nonce string) {
	hdr := w.Header()
	if nonce != "" {
		hdr.Set(dispatch.HeaderNonce, nonce)
	}
	if txn != "" {
		hdr.Set(headerTransaction, txn)
	}
	if s := decision(d); s != "" {
		hdr.Set(headerDecision, s)
	}
	mode := "enforce"
	if monitor {
		mode = "monitor"
	}
	hdr.Set(headerMode, mode)
}

func decision(d pb.Decision) string {
	if d == pb.Decision_DECISION_UNSPECIFIED {
		return ""
	}
	return strings.TrimPrefix(d.String(), "DECISION_")
}

// redactor passes bytes on with the placed key removed (HR-076): a key
// split between two reads is caught by holding back only a tail that could
// begin it, so a stream is not delayed otherwise.
type redactor struct {
	w      io.Writer
	secret []byte
	held   []byte
}

func (r *redactor) Write(p []byte) error {
	if len(r.secret) == 0 {
		_, err := r.w.Write(p)
		return err
	}
	buf := append(bytes.Clone(r.held), p...)
	buf = bytes.ReplaceAll(buf, r.secret, []byte("[REDACTED]"))
	keep := 0
	for k := min(len(buf), len(r.secret)-1); k > 0; k-- {
		if bytes.HasPrefix(r.secret, buf[len(buf)-k:]) {
			keep = k
			break
		}
	}
	r.held = bytes.Clone(buf[len(buf)-keep:])
	_, err := r.w.Write(buf[:len(buf)-keep])
	return err
}

// Close passes on what was held back.
func (r *redactor) Close() error {
	if len(r.held) == 0 {
		return nil
	}
	_, err := r.w.Write(r.held)
	r.held = nil
	return err
}

// refusal is a refusal before or instead of an answer.
type refusal struct {
	code, txn string
	class     dispatch.Class
	expl      *dispatch.Explanation
}

func fail(code string) refusal {
	return refusal{code: code, class: dispatch.CannotAuthorize}
}

// refuseResult answers a result that passed no answer on (D819).
func (h *Handler) refuseResult(w http.ResponseWriter, r *http.Request, api modelapi.API, res dispatch.Result) {
	if res.Class == dispatch.AuthenticationFailed {
		h.refusePAP(w, r, api, res.PAPError, res.Nonce)
		return
	}
	h.facts(w, res.TransactionID, res.Decision, res.Monitor, res.Nonce)
	status, typ, retry := statusOf(res)
	if retry {
		w.Header().Set("Retry-After", "1")
	}
	refuse(w, api, status, typ, refusal{
		code: res.Code, txn: res.TransactionID, class: res.Class, expl: dispatch.ExplanationOf(res.Explanation),
	})
}

// containment codes refuse as permission errors (D819).
var containment = []string{
	dispatch.CodeKillSwitch, dispatch.CodeGatewayRevoked, dispatch.CodeContainmentStale, dispatch.CodeConnectionQuarantined,
	dispatch.CodeCircuitOpen,
}

// retryable reports a CANNOT_AUTHORIZE an SDK may retry (D819): the budget
// busy, the Authority or a check it needs unavailable.
func retryable(code string) bool {
	return code == "BUDGET_BUSY" || code == dispatch.CodeAuthorityUnavailable || code == dispatch.CodeFactsUnreported ||
		strings.HasSuffix(code, "_UNAVAILABLE")
}

// statusOf is a refusal's status, the provider's error type and whether
// Retry-After goes with it (D819).
func statusOf(res dispatch.Result) (int, string, bool) {
	switch res.Class {
	case dispatch.PolicyDenied, dispatch.Held:
		return http.StatusForbidden, "permission_error", false
	case dispatch.CannotAuthorize:
		if retryable(res.Code) || (len(res.Reasons) > 0 && retryable(res.Reasons[0])) {
			return http.StatusServiceUnavailable, "api_error", true
		}
		return http.StatusForbidden, "permission_error", false
	case dispatch.EnforcementFailed:
		for _, c := range containment {
			if res.Code == c {
				return http.StatusForbidden, "permission_error", false
			}
		}
		return http.StatusBadGateway, "api_error", false
	case dispatch.Uncertain:
		return http.StatusGatewayTimeout, "api_error", false
	case dispatch.ToolFailed, dispatch.AuthenticationFailed:
	}
	return http.StatusBadGateway, "api_error", false
}

// refusePAP answers 401 with a PAP-Error code and a nonce (PAP-1 §12), in
// the provider's shape.
func (h *Handler) refusePAP(w http.ResponseWriter, r *http.Request, api modelapi.API, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = h.engine.Nonce(r.Context())
	}
	if nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, nonce)
	}
	w.Header().Set(dispatch.HeaderError, string(code))
	refuse(w, api, http.StatusUnauthorized, "authentication_error", refusal{code: string(code), class: dispatch.AuthenticationFailed})
}

// presentation is how a refusal presents (HR-400).
func (f refusal) presentation() string {
	if f.expl != nil && f.expl.Presentation != "" {
		return f.expl.Presentation
	}
	switch f.class {
	case dispatch.PolicyDenied:
		return "deny"
	case dispatch.Held:
		return "hold"
	case dispatch.AuthenticationFailed:
		return "authentication_failed"
	case dispatch.CannotAuthorize, dispatch.EnforcementFailed, dispatch.ToolFailed, dispatch.Uncertain:
		return "cannot_authorize"
	default:
		return "cannot_authorize"
	}
}

type anthropicError struct {
	Type  string `json:"type"`
	Error struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
	PantherClaw *dispatch.Explanation `json:"pantherclaw"`
}

type openAIError struct {
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code"`
	} `json:"error"`
	PantherClaw *dispatch.Explanation `json:"pantherclaw"`
}

// refuse writes a refusal in the provider's error shape (D819): message
// "PantherClaw: <presentation> (<code>, transaction <id>)" and the
// agent-safe explanation, never budget values or content (HR-400).
func refuse(w http.ResponseWriter, api modelapi.API, status int, typ string, f refusal) {
	expl := f.expl
	code := f.code
	if expl != nil && expl.DecisiveCode != "" {
		code = expl.DecisiveCode
	}
	if expl == nil {
		expl = &dispatch.Explanation{Presentation: f.presentation(), DecisiveCode: code, TransactionID: f.txn, NextActions: []dispatch.NextAction{}}
	}
	msg := "PantherClaw: " + f.presentation() + " (" + code
	if f.txn != "" {
		msg += ", transaction " + f.txn
	}
	msg += ")"
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if api.Anthropic() {
		var out anthropicError
		out.Type, out.Error.Type, out.Error.Message, out.PantherClaw = "error", typ, msg, expl
		_ = json.MarshalWrite(w, out)
		return
	}
	var out openAIError
	out.Error.Message, out.Error.Type, out.Error.Code, out.PantherClaw = msg, typ, code, expl
	_ = json.MarshalWrite(w, out)
}
