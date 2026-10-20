// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"log/slog"
	"slices"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
	"github.com/katocxl/pantherclaw/internal/gateway/egress"
	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// The gateway's data scope engine (G0 M14 D20; F101–F103, HR-310,
// HR-311). The Authority attaches a record_scope and a data_classes
// obligation when a grant or a policy limits what a read may return; the
// gateway applies them to what the target answers before the agent sees
// it:
//
//   - record_scope on a postgres connection adds the mandatory predicate
//     on the scope column of the table whose scope key the obligation
//     names (pgdispatch); anywhere else it cannot be enforced, and nothing
//     is sent (SCOPE_UNSUPPORTED);
//   - data_classes withholds every value of a class it does not allow:
//     postgres columns are never selected, JSON answer values (and whole
//     subtrees a declared path covers, D73) become "[redacted:<class>]";
//   - secret is always withheld from postgres answers, and from JSON
//     answers under a data_classes obligation.
//
// A JSON answer the engine cannot read (not JSON, or cut at the size cap)
// is withheld from the agent under an obligation: the outcome is still
// recorded, and the agent gets SCOPE_UNENFORCEABLE.

// Scope codes.
const (
	// CodeScopeUnsupported: a scope obligation the route cannot enforce.
	CodeScopeUnsupported = "scope_unsupported"
	// CodeScopeUnenforceable: the answer could not be scoped, so it was
	// withheld; the action ran and its outcome is recorded.
	CodeScopeUnenforceable = "scope_unenforceable"
)

// Obligation kinds the scope engine applies (pdomain.RecordScope,
// pdomain.DataClasses).
const (
	obligationRecordScope = "record_scope"
	obligationDataClasses = "data_classes"
)

// scopeObligation reports whether the scope engine applies an obligation,
// so that effective leaves it alone.
func scopeObligation(o *pb.Obligation) bool {
	return o.GetKind() == obligationRecordScope || o.GetKind() == obligationDataClasses
}

// dataScope is a dispatch's scope: nil records and classes when no
// obligation limits it.
type dataScope struct {
	records *pgdispatch.RecordScope
	classes []pgdispatch.Class
}

type scopeKey struct{}

// readable reports whether a JSON answer value of class may reach the agent.
func (s *dataScope) readable(class string) bool {
	return class != string(pgdispatch.ClassSecret) && slices.Contains(s.classes, pgdispatch.Class(class))
}

// withScope puts a dispatch's scope obligations on ctx. A record scope
// anywhere but a postgres connection, a scope on a definition that does
// not declare it, a second obligation of a kind, or a malformed one cannot
// be applied: the dispatch is refused before anything is sent (HR-302).
func withScope(ctx context.Context, conn *control.Connection, def *defs.Definition, obligations []*pb.Obligation) (context.Context, string) {
	var s dataScope
	seen := map[string]bool{}
	for _, o := range obligations {
		if !scopeObligation(o) {
			continue
		}
		if seen[o.GetKind()] || (o.GetTiming() != "" && o.GetTiming() != "before_execution") || def.Access != defs.AccessRead {
			return ctx, CodeScopeUnsupported
		}
		seen[o.GetKind()] = true
		switch o.GetKind() {
		case obligationRecordScope:
			if conn.GetKind() != "postgres" || !slices.Contains(def.Scoping, "records") || !pgdispatch.ValidIdentifier(o.GetParam()) {
				return ctx, CodeScopeUnsupported
			}
			s.records = &pgdispatch.RecordScope{Key: o.GetParam(), Values: slices.Clone(o.GetValues())}
		case obligationDataClasses:
			if !slices.Contains(def.Scoping, "classes") {
				return ctx, CodeScopeUnsupported
			}
			s.classes = []pgdispatch.Class{}
			for _, v := range o.GetValues() {
				if !slices.Contains([]string{"public", "internal", "pii"}, v) {
					return ctx, CodeScopeUnsupported
				}
				s.classes = append(s.classes, pgdispatch.Class(v))
			}
		}
	}
	if len(seen) == 0 {
		return ctx, ""
	}
	return context.WithValue(ctx, scopeKey{}, &s), ""
}

// scopeOf is the dispatch's scope, nil without one.
func scopeOf(ctx context.Context) *dataScope {
	s, _ := ctx.Value(scopeKey{}).(*dataScope)
	return s
}

// pgAccess is what a postgres read may return under the scope.
func (s *dataScope) pgAccess() (pgdispatch.Access, *pgdispatch.RecordScope) {
	if s == nil {
		return pgdispatch.Access{}, nil
	}
	return pgdispatch.Access{Classes: s.classes}, s.records
}

// scopeHTTP applies the dispatch's data_classes scope to a target's answer,
// in place. With no scope, or only an answer status, the answer is left
// as it is. It returns the class and code to record: the given ones, or a
// refusal when the answer was withheld.
func (e *Engine) scopeHTTP(ctx context.Context, conn *control.Connection, def *defs.Definition, res *egress.Response, class Class, code string) (Class, string) {
	s := scopeOf(ctx)
	if s == nil || s.classes == nil || len(res.Body) == 0 {
		return class, code
	}
	body, redacted, ok := scopeJSON(res.Body, res.Truncated, def.Response, s)
	if !ok {
		e.log.WarnContext(ctx, "gateway.scope_unenforceable", slog.String("connection_id", conn.GetId()), slog.String("operation", def.Operation))
		res.Body, res.ContentType, res.Truncated = nil, "", false
		return EnforcementFailed, CodeScopeUnenforceable
	}
	res.Body = body
	e.log.InfoContext(ctx, "gateway.scope_applied", slog.String("connection_id", conn.GetId()), slog.String("operation", def.Operation),
		slog.Int("values_redacted", redacted))
	return class, code
}

// scopeJSON redacts every value of a JSON answer whose class the scope
// does not allow: the class of a value is the strictest declared field
// covering its path (D73), and a value covered by a disallowed class is
// replaced whole, subtree included. ok is false for an answer that is not
// one JSON value or was cut at the size cap.
func scopeJSON(body []byte, truncated bool, spec *defs.ResponseSpec, s *dataScope) ([]byte, int, bool) {
	if truncated {
		return nil, 0, false
	}
	n := 0
	// Scalars keep their exact bytes (a large integer stays exact); objects
	// and arrays are rebuilt, duplicate members refused as ambiguous.
	var walk func(v jsontext.Value, path []string) (jsontext.Value, error)
	walk = func(v jsontext.Value, path []string) (jsontext.Value, error) {
		if c := spec.ClassOf(path); !s.readable(c) && (len(path) > 0 || c != "public") {
			n++
			return json.Marshal(pgdispatch.Redacted(pgdispatch.Class(c)))
		}
		switch v.Kind() {
		case '{':
			var m map[string]jsontext.Value
			if err := json.Unmarshal(v, &m); err != nil {
				return nil, err
			}
			for k, val := range m {
				w, err := walk(val, append(slices.Clone(path), k))
				if err != nil {
					return nil, err
				}
				m[k] = w
			}
			return json.Marshal(m, json.Deterministic(true))
		case '[':
			var a []jsontext.Value
			if err := json.Unmarshal(v, &a); err != nil {
				return nil, err
			}
			for i, val := range a {
				w, err := walk(val, append(slices.Clone(path), "*"))
				if err != nil {
					return nil, err
				}
				a[i] = w
			}
			return json.Marshal(a)
		}
		return v, nil
	}
	v := jsontext.Value(body)
	if !v.IsValid() {
		return nil, 0, false
	}
	out, err := walk(v.Clone(), nil)
	if err != nil {
		return nil, 0, false
	}
	return out, n, true
}
