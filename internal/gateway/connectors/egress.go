// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package connectors

import (
	"context"
	"crypto/subtle"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/mapping"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
)

// Egress sends a connector's mediated request through its egress
// connection (dispatch.Engine).
type Egress interface {
	ConnectorEgress(ctx context.Context, conn *control.Connection, a actionir.Parsed, txn string) (egress.Response, error)
}

// WithEgress sends connectors' mediated requests through e.
func (s *Supervisor) WithEgress(e Egress) *Supervisor {
	s.send = e
	return s
}

// Fly implements dispatch.Connectors: the connector's egress is bound to f
// until land is called.
func (s *Supervisor) Fly(connection string, f dispatch.Flight) (land func()) {
	s.mu.Lock()
	in, ok := s.running[connection]
	if ok {
		in.flight = &f
	}
	s.mu.Unlock()
	if !ok {
		return func() {}
	}
	return func() {
		s.mu.Lock()
		if in.flight == &f {
			in.flight = nil
		}
		s.mu.Unlock()
	}
}

// Egress refusal codes.
const (
	codeUnknownBinding = "unknown_binding"
	codeNotInFlight    = "no_call_in_flight"
	codeUnmapped       = "unmapped_request"
	codeOutsideTheCall = "outside_the_call"
	codeNotSent        = "not_sent"
	codeContained      = "contained"
)

// egressHandler serves the egress listener: a connector's edge sends each
// request the connector made (edge.EgressPath). It is accepted only with a
// running connector's binding token, while a call to that connector is in
// flight, when it maps through the connector's egress connection to the
// call's operation on the call's target, or to a reviewed read of that
// target (G0 M9 design decision 6). Everything else is refused and logged
// as a finding.
func (s *Supervisor) egressHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != edge.EgressPath {
			http.NotFound(w, r)
			return
		}
		in, f := s.byBinding(r.Header.Get(edge.HeaderBinding))
		switch {
		case in == nil:
			s.refuse(w, r, "", codeUnknownBinding, http.StatusForbidden)
			return
		case f == nil:
			s.refuse(w, r, in.connection, codeNotInFlight, http.StatusForbidden)
			return
		}
		var req edge.Egress
		if err := json.UnmarshalRead(io.LimitReader(r.Body, 2*edge.MaxEgressBody), &req); err != nil {
			s.refuse(w, r, in.connection, codeUnmapped, http.StatusBadRequest)
			return
		}
		cfg := s.conf.Current()
		var conn *control.Connection
		if cfg != nil {
			conn = cfg.ByID[in.egress]
		}
		if conn == nil || conn.GetName() != req.Connection || conn.Mapper == nil {
			s.refuse(w, r, in.connection, codeUnmapped, http.StatusForbidden)
			return
		}
		a := f.Action
		p, err := conn.Mapper.HTTP(r.Context(), mapping.Context{
			Org: a.Org, Env: a.Env, RunID: a.RunID, ActionID: a.ActionID, AgentInstance: a.AgentInstance, Connection: conn.GetId(),
		}, req.Method, req.Path, req.Query, req.Body)
		if err != nil {
			s.refuse(w, r, in.connection, codeUnmapped, http.StatusForbidden)
			return
		}
		if !within(conn, p.Action, a) {
			s.log.WarnContext(r.Context(), "gateway.connector_egress_refused", slog.String("connection", in.connection),
				slog.String("transaction_id", f.Txn), slog.String("operation", p.Action.Operation), slog.String("code", codeOutsideTheCall))
			s.refuse(w, r, in.connection, codeOutsideTheCall, http.StatusForbidden)
			return
		}
		if s.send == nil {
			s.refuse(w, r, in.connection, codeNotSent, http.StatusServiceUnavailable)
			return
		}
		res, err := s.send.ConnectorEgress(r.Context(), conn, p, f.Txn)
		switch {
		case errors.Is(err, dispatch.ErrEgressContained):
			s.refuse(w, r, in.connection, codeContained, http.StatusForbidden)
			return
		case errors.Is(err, egress.ErrBuild):
			s.refuse(w, r, in.connection, codeNotSent, http.StatusForbidden)
			return
		case err != nil && res.Status == 0:
			s.refuse(w, r, in.connection, codeNotSent, http.StatusBadGateway)
			return
		}
		if res.ContentType != "" {
			w.Header().Set("Content-Type", res.ContentType)
		}
		w.WriteHeader(res.Status)
		_, _ = w.Write(res.Body)
	})
}

// within reports whether an egress request's action is the call's: the
// same operation on the same target, or a reviewed read of that target.
func within(conn *control.Connection, got, call actionir.ActionIR) bool {
	if got.Target != call.Target {
		return false
	}
	if got.Operation == call.Operation {
		return true
	}
	def, ok := conn.Package.Definition(got.Operation)
	return ok && def.Access == domain.AccessRead
}

// byBinding finds the running connector whose binding token this is, and
// the call in flight on it.
func (s *Supervisor) byBinding(token string) (*instance, *dispatch.Flight) {
	if token == "" {
		return nil, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, in := range s.running {
		if in.binding != "" && subtle.ConstantTimeCompare([]byte(in.binding), []byte(token)) == 1 {
			return in, in.flight
		}
	}
	return nil, nil
}

func (s *Supervisor) refuse(w http.ResponseWriter, r *http.Request, connection, code string, status int) {
	s.log.WarnContext(r.Context(), "gateway.connector_egress_refused", slog.String("connection", connection), slog.String("code", code))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(edge.HeaderRefusedBy, "gateway")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error_class": string(dispatch.CannotAuthorize), "error": code})
}
