// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package modelface is the gateway's model face (G0 M25 D313, founder
// decision H10): `/model/{connection}/{host}/…` carries a range agent's
// model calls, during an open campaign, to the campaign's model relay. It is
// a written exception to HR-075: the bytes go to the relay unchanged and
// stream back, with no ActionIR, no Authority decision and no transaction,
// and the gateway's payload scan does not see them.
//
// Every request is PAP/1-verified by the Authority (HR-021) and then asked of
// the server, which refuses unless the connection is a simulated model relay
// this gateway serves, the run is a simulated run of a range agent, and that
// agent's open campaign names this relay and this host. The server counts
// requests and bytes each way, never content. A real connection, a real
// agent, or a closed campaign never gets through, and with no campaign open
// the route is off. Containment stops it like any dispatch (HR-010). A body
// is at most 8 MiB each way.
package modelface

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/identity/pap"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// MaxBody is the most a request or an answer may carry (D313).
const MaxBody = 8 << 20

// Prefix is the face's first path segment, a reserved connection name.
const Prefix = "/model/"

// Codes of the face's refusals.
const (
	CodeUnknownConnection = "unknown_connection"
	CodeBodyTooLarge      = "body_too_large"
	CodeRunRequired       = "run_id_required"
	CodeRouteClosed       = "model_route_closed"
	CodeUnverified        = "simulator_unverified"
	CodeUnreachable       = "relay_unreachable"
	CodeAuthorityDown     = "authority_unavailable"
)

// requestHeaders are the only request headers passed to the relay: no
// credential, cookie or forwarding header ever is.
var requestHeaders = []string{"Content-Type", "Accept", "Anthropic-Version", "Anthropic-Beta", "Openai-Beta"}

// answerHeaders are the only answer headers passed back.
var answerHeaders = []string{"Content-Type", "Cache-Control", "Retry-After", "Request-Id", "X-Request-Id"}

var hostRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$`)

// Engine is the part of the dispatch engine the face uses.
type Engine interface {
	Nonce(ctx context.Context) string
	ReportUnknown(ctx context.Context, creds *pb.WorkloadCredentials, userAgent, route string) (pap.Code, string)
	Verify(ctx context.Context, creds *pb.WorkloadCredentials, run string) (dispatch.Verified, error)
	ModelContained(conn *control.Connection) string
	ModelClient(ctx context.Context, conn *control.Connection) (*egress.Client, bool)
}

// Control is the server's side of the route (GatewayService).
type Control interface {
	// Authorize decides and counts one request; it returns the campaign.
	Authorize(ctx context.Context, connection, run, host string, bytesToModel int64) (string, error)
	// Report adds the answer's size.
	Report(ctx context.Context, campaign, run string, bytesFromModel int64) error
}

// Configuration is the gateway's current configuration.
type Configuration interface {
	Current() *control.Config
}

// Handler serves the model face.
type Handler struct {
	engine    Engine
	control   Control
	config    Configuration
	publicURL string
	log       *slog.Logger
}

// New returns the model face. With no control it refuses everything.
func New(engine Engine, ctl Control, config Configuration, publicURL string, log *slog.Logger) *Handler {
	if log == nil {
		log = pclog.Discard()
	}
	return &Handler{engine: engine, control: ctl, config: config, publicURL: strings.TrimSuffix(publicURL, "/"), log: log}
}

// Path splits an escaped path of the face into the connection, the model
// host and the rest, which keeps its leading slash.
func Path(escaped string) (conn, host, rest string, ok bool) {
	s, found := strings.CutPrefix(escaped, Prefix)
	if !found {
		return "", "", "", false
	}
	conn, s, _ = strings.Cut(s, "/")
	host, rest, _ = strings.Cut(s, "/")
	rest = "/" + rest
	if conn == "" || strings.Contains(conn, "%") || !hostRE.MatchString(host) {
		return "", "", "", false
	}
	return conn, host, rest, true
}

// Refusal is the JSON body of a refusal.
type Refusal struct {
	ErrorClass string `json:"error_class"`
	Error      string `json:"error"`
}

func refuse(w http.ResponseWriter, status int, class dispatch.Class, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, Refusal{ErrorClass: string(class), Error: code})
}

func (h *Handler) refusePAP(w http.ResponseWriter, r *http.Request, code pap.Code, nonce string) {
	if nonce == "" {
		nonce = h.engine.Nonce(r.Context())
	}
	if nonce != "" {
		w.Header().Set(dispatch.HeaderNonce, nonce)
	}
	w.Header().Set(dispatch.HeaderError, string(code))
	refuse(w, http.StatusUnauthorized, dispatch.AuthenticationFailed, string(code))
}

// ServeHTTP serves one model call.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	name, host, rest, ok := Path(r.URL.EscapedPath())
	var conn *control.Connection
	if cfg := h.config.Current(); ok && cfg != nil {
		conn = cfg.ByName[name]
	}
	if !dispatch.IsModelRelay(conn) || h.control == nil {
		refuse(w, http.StatusNotFound, dispatch.CannotAuthorize, CodeUnknownConnection)
		return
	}
	if r.Header.Get("Upgrade") != "" {
		refuse(w, http.StatusForbidden, dispatch.CannotAuthorize, CodeRouteClosed)
		return
	}
	// The raw body is hashed for the proof before anything else (HR-091).
	body, err := io.ReadAll(io.LimitReader(r.Body, MaxBody+1))
	if err != nil || len(body) > MaxBody {
		refuse(w, http.StatusRequestEntityTooLarge, dispatch.CannotAuthorize, CodeBodyTooLarge)
		return
	}
	in := dispatch.ReadInbound(r, body, h.publicURL+r.URL.Path)
	switch {
	case in.Creds.GetProof() == "":
		h.refusePAP(w, r, pap.CodeUseNonce, "")
		return
	case !in.HasToken:
		code, nonce := h.engine.ReportUnknown(ctx, in.Creds, r.UserAgent(), "")
		h.refusePAP(w, r, code, nonce)
		return
	case !in.SubjectOK:
		h.refusePAP(w, r, pap.CodeInvalidToken, "")
		return
	case in.Run == "":
		refuse(w, http.StatusBadRequest, dispatch.CannotAuthorize, CodeRunRequired)
		return
	}
	v, err := h.engine.Verify(ctx, in.Creds, in.Run)
	if err != nil {
		refuse(w, http.StatusServiceUnavailable, dispatch.EnforcementFailed, CodeAuthorityDown)
		return
	}
	if !v.OK {
		h.refusePAP(w, r, v.Code, v.Nonce)
		return
	}
	if code := h.engine.ModelContained(conn); code != "" {
		refuse(w, http.StatusServiceUnavailable, dispatch.EnforcementFailed, code)
		return
	}
	campaign, err := h.control.Authorize(ctx, conn.GetId(), in.Run, host, int64(len(body)))
	if err != nil {
		h.log.WarnContext(ctx, "gateway.model_call_refused", slog.String("connection_id", conn.GetId()), slog.String("run_id", in.Run))
		refuse(w, http.StatusForbidden, dispatch.CannotAuthorize, CodeRouteClosed)
		return
	}
	cl, ok := h.engine.ModelClient(ctx, conn)
	if !ok {
		refuse(w, http.StatusForbidden, dispatch.CannotAuthorize, CodeUnverified)
		return
	}
	var n int64
	// Reported also when a cut stream aborts the handler.
	defer func() {
		if err := h.control.Report(context.WithoutCancel(ctx), campaign, in.Run, n); err != nil {
			h.log.WarnContext(ctx, "gateway.model_usage_not_reported", slog.String("run_id", in.Run), pclog.Err(err))
		}
	}()
	h.forward(w, r, cl, conn, rest, body, &n)
}

// forward sends the request to the relay and streams the answer back,
// counting the answer bytes passed on in n.
func (h *Handler) forward(w http.ResponseWriter, r *http.Request, cl *egress.Client, conn *control.Connection, rest string, body []byte, n *int64) {
	ctx, cancel := context.WithTimeout(r.Context(), dispatch.ModelCallTimeout)
	defer cancel()
	target := strings.TrimSuffix(conn.GetBaseUrl(), "/") + rest
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	u, err := url.Parse(target)
	if err != nil {
		refuse(w, http.StatusBadRequest, dispatch.CannotAuthorize, CodeUnknownConnection)
		return
	}
	headers := map[string]string{}
	for _, k := range requestHeaders {
		if v := r.Header.Get(k); v != "" && k != "Content-Type" {
			headers[k] = v
		}
	}
	req, err := cl.HTTPRequest(ctx, egress.Request{
		Method: r.Method, URL: u, Body: bodyOrNil(body), ContentType: r.Header.Get("Content-Type"), Headers: headers,
	})
	if err != nil {
		refuse(w, http.StatusBadRequest, dispatch.CannotAuthorize, CodeUnknownConnection)
		return
	}
	res, err := cl.Open(req)
	if err != nil {
		refuse(w, http.StatusBadGateway, dispatch.EnforcementFailed, CodeUnreachable)
		return
	}
	defer func() { _ = res.Body.Close() }()
	for _, k := range answerHeaders {
		if v := res.Header.Get(k); v != "" {
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 32<<10)
	for {
		k, rerr := res.Body.Read(buf)
		if k > 0 {
			if _, werr := w.Write(buf[:k]); werr != nil {
				return
			}
			*n += int64(k)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if errors.Is(rerr, io.EOF) {
			return
		}
		if rerr != nil {
			// A cut stream must not read as a whole one: the agent's
			// connection is broken (egress.ErrTooLarge past 8 MiB).
			h.log.WarnContext(ctx, "gateway.model_answer_cut", slog.String("connection_id", conn.GetId()), pclog.Err(rerr))
			panic(http.ErrAbortHandler)
		}
	}
}

func bodyOrNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}
