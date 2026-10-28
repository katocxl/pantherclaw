// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package rpc sets up the Connect RPC server (ADR-0005) with PantherClaw's
// interceptor chain, outermost first:
//
//  1. recovery: a panic becomes CodeInternal "internal error";
//  2. request id: a validated X-Request-Id is echoed or a new one minted, and
//     both it and the procedure are attached to the log context;
//  3. logging and tracing: one rpc.call record and one span per call;
//  4. error mapping: platform errors become stable codes with client-safe
//     messages; anything else becomes CodeInternal "internal error";
//  5. authentication: only procedures declared public run unauthenticated
//     (real authentication arrives in M2);
//  6. validation: every request message is checked with protovalidate
//     before the handler sees it (HR-104).
package rpc

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strings"
	"time"

	"buf.build/go/protovalidate"
	"connectrpc.com/connect/v2"
	"connectrpc.com/connect/v2/connecthttp"
	"connectrpc.com/connect/v2/connectproto"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/telemetry"
)

// Limits on message sizes.
const (
	MaxRequestBytes  = 1 << 20
	MaxResponseBytes = 4 << 20
	// RequestIDHeader carries the request id in both directions.
	RequestIDHeader = "X-Request-Id"
)

var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Authenticator authenticates a non-public call (M2). It returns the context
// carrying the authenticated principal, or an error.
type Authenticator func(ctx context.Context, info *connect.CallInfo, spec connect.Spec) (context.Context, error)

// Options configures the server.
type Options struct {
	Logger *slog.Logger
	// Public lists procedures callable without authentication. Each must also
	// be declared "// permission: public" in its proto (tested).
	Public []string
	// Authenticate authenticates every non-public procedure. When it is nil,
	// every non-public procedure is refused.
	Authenticate Authenticator
}

// NewServer returns a connect.Server with the PantherClaw interceptor chain.
func NewServer(opts Options) (*connect.Server, error) {
	log := opts.Logger
	if log == nil {
		log = pclog.Discard()
	}
	v, err := protovalidate.New()
	if err != nil {
		return nil, fmt.Errorf("rpc: protovalidate: %w", err)
	}
	public := slices.Clone(opts.Public)
	return connect.NewServer(
		recoverInterceptor(log),
		requestIDInterceptor,
		observeInterceptor(log),
		errorInterceptor(log),
		authInterceptor(public, opts.Authenticate),
		validateInterceptor(v),
	), nil
}

// Mount installs the server's procedures on mux with message size limits.
// Every route answers POST only, and JSON requests with unknown fields are
// refused (strictJSON).
func Mount(mux *http.ServeMux, s *connect.Server) {
	connecthttp.Mount(postOnly{mux}, s,
		connecthttp.WithCodecs(connectproto.NewBinaryCodec(), newStrictJSON()),
		connecthttp.WithReadMaxBytes(MaxRequestBytes), connecthttp.WithSendMaxBytes(MaxResponseBytes))
}

// postOnly registers each Connect route behind a POST check. Connect would
// also serve GET for NO_SIDE_EFFECTS methods; no client uses it, browser
// sessions are POST-only (HR-342), and the published schema lists POST, so
// any other method gets a bodiless 405 with Allow: POST.
type postOnly struct{ mux *http.ServeMux }

func (p postOnly) Handle(pattern string, h http.Handler) {
	p.mux.Handle(pattern, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.ServeHTTP(w, r)
	}))
}

func recoverInterceptor(log *slog.Logger) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) (err error) {
			defer func() {
				if r := recover(); r != nil {
					log.ErrorContext(ctx, "rpc.panic", slog.String("procedure", spec.Procedure),
						slog.String("panic", fmt.Sprint(r)), slog.String("stack", string(debug.Stack())))
					err = connect.NewError(connect.CodeInternal, "internal error")
				}
			}()
			return next(ctx, spec, stream)
		}
	}
}

func requestIDInterceptor(next connect.ServerFunc) connect.ServerFunc {
	return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
		id := ""
		if info, ok := connect.CallInfoForServerContext(ctx); ok {
			id = info.RequestHeader().Get(RequestIDHeader)
			if !requestIDPattern.MatchString(id) {
				id = ids.NewV7().String()
			}
			info.ResponseHeader().Set(RequestIDHeader, id)
		}
		ctx = pclog.WithAttrs(ctx, slog.String(pclog.KeyRequestID, id), slog.String("procedure", spec.Procedure))
		return next(ctx, spec, stream)
	}
}

func observeInterceptor(log *slog.Logger) connect.ServerInterceptor {
	tracer := otel.Tracer("github.com/katocxl/pantherclaw/internal/platform/rpc")
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			start := time.Now()
			ctx, span := tracer.Start(ctx, strings.TrimPrefix(spec.Procedure, "/"),
				trace.WithSpanKind(trace.SpanKindServer), trace.WithAttributes(attribute.String(telemetry.KeyProcedure, spec.Procedure)))
			defer span.End()
			err := next(ctx, spec, stream)
			code := "ok"
			level := slog.LevelInfo
			if err != nil {
				code = connect.CodeOf(err).String()
				span.SetStatus(codes.Error, code)
				if connect.CodeOf(err) == connect.CodeInternal || connect.CodeOf(err) == connect.CodeUnknown {
					level = slog.LevelError
				}
			}
			span.SetAttributes(attribute.String(telemetry.KeyCode, code))
			telemetry.RPC(ctx, spec.Procedure, code, time.Since(start))
			log.Log(ctx, level, "rpc.call", slog.String(pclog.KeyOutcome, code),
				slog.Int64("duration_ms", time.Since(start).Milliseconds()))
			return err
		}
	}
}

// errorInterceptor converts handler errors to wire errors. Only messages a
// developer wrote on purpose (pcerr / connect errors) reach the client.
func errorInterceptor(log *slog.Logger) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			err := next(ctx, spec, stream)
			if err == nil {
				return nil
			}
			var ce *connect.Error
			if errors.As(err, &ce) {
				return err
			}
			code := pcerr.CodeOf(err)
			if code == pcerr.Internal {
				log.ErrorContext(ctx, "rpc.internal_error", pclog.Err(err))
			}
			msg := pcerr.PublicMessage(err)
			if reason := pcerr.ReasonOf(err); reason != "" && code != pcerr.Internal {
				msg = reason + ": " + msg
			}
			return connect.NewError(ConnectCode(code), msg).WithCause(err)
		}
	}
}

// ConnectCode maps a platform error code to a Connect code. Security
// decisions keep a distinct, stable mapping: DENY is PermissionDenied (a
// known prohibition, not retryable) and CANNOT_AUTHORIZE is Unavailable
// (missing evidence or dependency, retryable); both messages carry the
// reason (BUILD_GUIDE §3.1).
func ConnectCode(c pcerr.Code) connect.Code {
	switch c {
	case pcerr.InvalidArgument:
		return connect.CodeInvalidArgument
	case pcerr.NotFound:
		return connect.CodeNotFound
	case pcerr.AlreadyExists:
		return connect.CodeAlreadyExists
	case pcerr.PermissionDenied, pcerr.Deny:
		return connect.CodePermissionDenied
	case pcerr.Unauthenticated:
		return connect.CodeUnauthenticated
	case pcerr.FailedPrecondition:
		return connect.CodeFailedPrecondition
	case pcerr.Aborted:
		return connect.CodeAborted
	case pcerr.ResourceExhausted:
		return connect.CodeResourceExhausted
	case pcerr.Canceled:
		return connect.CodeCanceled
	case pcerr.DeadlineExceeded:
		return connect.CodeDeadlineExceeded
	case pcerr.Unavailable, pcerr.CannotAuthorize:
		return connect.CodeUnavailable
	case pcerr.Unimplemented:
		return connect.CodeUnimplemented
	case pcerr.Internal:
		return connect.CodeInternal
	default:
		return connect.CodeInternal
	}
}

func authInterceptor(public []string, authenticate Authenticator) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			if slices.Contains(public, spec.Procedure) {
				return next(ctx, spec, stream)
			}
			if authenticate == nil {
				return connect.NewError(connect.CodeUnauthenticated, "authentication required")
			}
			info, ok := connect.CallInfoForServerContext(ctx)
			if !ok {
				return connect.NewError(connect.CodeUnauthenticated, "authentication required")
			}
			actx, err := authenticate(ctx, info, spec)
			if err != nil {
				return err
			}
			return next(actx, spec, stream)
		}
	}
}

// validateInterceptor checks every received request message (HR-104). The
// error names the violated fields and rules, never the submitted values.
func validateInterceptor(v protovalidate.Validator) connect.ServerInterceptor {
	return func(next connect.ServerFunc) connect.ServerFunc {
		return func(ctx context.Context, spec connect.Spec, stream connect.ServerStream) error {
			return next(ctx, spec, &validatingStream{ServerStream: stream, v: v})
		}
	}
}

type validatingStream struct {
	connect.ServerStream
	v protovalidate.Validator
}

func (s *validatingStream) Receive(msg any) error {
	if err := s.ServerStream.Receive(msg); err != nil {
		return err
	}
	m, ok := msg.(proto.Message)
	if !ok {
		return connect.NewError(connect.CodeInternal, "internal error")
	}
	if err := s.v.Validate(m); err != nil {
		return invalidArgument(err)
	}
	return nil
}

func invalidArgument(err error) error {
	var verr *protovalidate.ValidationError
	if !errors.As(err, &verr) {
		return connect.NewError(connect.CodeInvalidArgument, "invalid request")
	}
	parts := make([]string, 0, len(verr.Violations))
	for _, v := range verr.Violations {
		p := v.Proto
		parts = append(parts, protovalidate.FieldPathString(p.GetField())+" ("+p.GetRuleId()+")")
	}
	return connect.NewError(connect.CodeInvalidArgument, "invalid request: "+strings.Join(parts, ", ")).WithCause(err)
}
