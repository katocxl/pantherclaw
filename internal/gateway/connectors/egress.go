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
	"sync"

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
	ConnectorEgress(ctx context.Context, conn *control.Connection, a actionir.Parsed, f dispatch.Flight) (egress.Response, error)
}

// WithEgress sends connectors' mediated requests through e.
func (s *Supervisor) WithEgress(e Egress) *Supervisor {
	s.send = e
	return s
}

// maxReads bounds the reads one call's egress makes.
const maxReads = 64

// flight is one call in flight on a connector and what its egress used:
// its one write, and its reads.
type flight struct {
	dispatch.Flight
	// landed is closed when the call lands (its answer came, or its window
	// closed): the call's egress requests end with it.
	landed chan struct{}
	wrote  bool
	reads  int
}

// Fly implements dispatch.Connectors: the connector's egress is bound to
// this call, and to it alone, until land is called. The connector takes
// one call at a time: Fly waits for the call before it to land, and a
// connector that stopped, or whose last exchange was abandoned, takes
// none (design decision 6).
func (s *Supervisor) Fly(ctx context.Context, connection string, f dispatch.Flight) (land func(), err error) {
	s.mu.Lock()
	in, ok := s.running[connection]
	s.mu.Unlock()
	if !ok || !in.stdio.Usable() {
		return nil, ErrNotRunning
	}
	select {
	case in.calls <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-in.done:
		return nil, ErrNotRunning
	}
	if !in.stdio.Usable() {
		<-in.calls
		return nil, ErrNotRunning
	}
	fl := &flight{Flight: f, landed: make(chan struct{})}
	s.mu.Lock()
	in.flight = fl
	s.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			in.flight = nil
			s.mu.Unlock()
			close(fl.landed)
			<-in.calls
		})
	}, nil
}

// Egress refusal codes.
const (
	codeUnknownBinding = "unknown_binding"
	codeNotInFlight    = "no_call_in_flight"
	codeUnmapped       = "unmapped_request"
	codeOutsideTheCall = "outside_the_call"
	codeRepeatedWrite  = "repeated_write"
	codeTooManyReads   = "too_many_reads"
	codeNotSent        = "not_sent"
	codeContained      = "contained"
)

// egressHandler serves the egress listener: a connector's edge sends each
// request the connector made (edge.EgressPath). It is accepted only with a
// running connector's binding token, while a call to that connector is in
// flight, when it maps through the connector's egress connection either
// to the call's bound action itself, once per call, or to a reviewed read
// of the call's target (G0 M9 design decision 6). Everything else is
// refused and logged as a finding.
func (s *Supervisor) egressHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != edge.EgressPath {
			http.NotFound(w, r)
			return
		}
		in, fl := s.byBinding(r.Header.Get(edge.HeaderBinding))
		switch {
		case in == nil:
			s.refuse(w, r, "", codeUnknownBinding, http.StatusForbidden)
			return
		case fl == nil:
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
		a := fl.Action.Action
		p, err := conn.Mapper.HTTP(r.Context(), mapping.Context{
			Org: a.Org, Env: a.Env, RunID: a.RunID, ActionID: a.ActionID, AgentInstance: a.AgentInstance, Connection: conn.GetId(),
		}, req.Method, req.Path, req.Query, req.Body)
		if err != nil {
			s.refuse(w, r, in.connection, codeUnmapped, http.StatusForbidden)
			return
		}
		write, ok := admit(conn, req.Method, p, fl.Action)
		code := ""
		s.mu.Lock()
		switch {
		case in.flight != fl:
			code = codeNotInFlight
		case !ok:
			code = codeOutsideTheCall
		case write && fl.wrote:
			code = codeRepeatedWrite
		case write:
			fl.wrote = true
		case fl.reads >= maxReads:
			code = codeTooManyReads
		default:
			fl.reads++
		}
		s.mu.Unlock()
		if code != "" {
			s.refuse(w, r, in.connection, code, http.StatusForbidden, slog.String("transaction_id", fl.Txn), slog.String("operation", p.Action.Operation))
			return
		}
		if s.send == nil {
			s.refuse(w, r, in.connection, codeNotSent, http.StatusServiceUnavailable)
			return
		}
		// The request ends when the call lands, or when the edge gives up.
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		sent := make(chan struct{})
		defer close(sent)
		go func() {
			select {
			case <-fl.landed:
				cancel()
			case <-sent:
			}
		}()
		res, err := s.send.ConnectorEgress(ctx, conn, p, fl.Flight)
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

// admit decides an egress request's action against the call: a reviewed
// read, over a safe method (GET or HEAD, so that a definition that marks a
// side-effecting POST as read cannot be repeated), is within the call when
// it reads the call's target; anything else is a write, within the call
// only when it is the call's bound action itself (sameAction).
func admit(conn *control.Connection, method string, got, call actionir.Parsed) (write, ok bool) {
	def, found := conn.Package.Definition(got.Action.Operation)
	switch {
	case !found:
		return false, false
	case def.Access == domain.AccessRead && (method == http.MethodGet || method == http.MethodHead):
		return false, got.Action.Target == call.Action.Target
	}
	return true, sameAction(got.Action, call.Action)
}

// sameAction reports whether an egress request's action is the call's
// bound action: the same action hash once the fields that only say how
// each one arrived (its connection, channel, route and definition) are
// the call's. Everything else must be equal: the operation, the target,
// the canonical parameters, the destinations, the dedupe key and the
// call's own ids.
func sameAction(got, call actionir.ActionIR) bool {
	got.Connection, got.Channel, got.Route, got.Definition = call.Connection, call.Channel, call.Route, call.Definition
	g, err := actionir.Encode(got)
	if err != nil {
		return false
	}
	c, err := actionir.Encode(call)
	return err == nil && g.Hash == c.Hash
}

// byBinding finds the running connector whose binding token this is, and
// the call in flight on it.
func (s *Supervisor) byBinding(token string) (*instance, *flight) {
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

// refuse answers a refused egress request and logs it as a finding, with
// the call's transaction and the operation when the request mapped.
func (s *Supervisor) refuse(w http.ResponseWriter, r *http.Request, connection, code string, status int, attrs ...any) {
	s.log.WarnContext(r.Context(), "gateway.connector_egress_refused", append([]any{slog.String("connection", connection), slog.String("code", code)}, attrs...)...)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set(edge.HeaderRefusedBy, "gateway")
	w.WriteHeader(status)
	_ = json.MarshalWrite(w, map[string]string{"error_class": string(dispatch.CannotAuthorize), "error": code})
}
