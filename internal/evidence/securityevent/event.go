// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package securityevent projects the closed security ledger set into the
// bounded, machine-readable restore log (G0 M13 D31, D41; HR-383).
package securityevent

import (
	"context"
	"encoding/json/v2"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Object identifies the exact security object, never its display name.
type Object struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Event is the public security_event NDJSON contract. RecordDigest is
// present only for D41 deletion records; no reasons or bodies are copied.
type Event struct {
	Timestamp        time.Time    `json:"ts"`
	Org              ids.OrgID    `json:"org"`
	LedgerSeq        int64        `json:"ledger_seq"`
	Kind             string       `json:"kind"`
	Direction        string       `json:"direction"`
	Object           Object       `json:"object"`
	Actor            domain.Actor `json:"actor"`
	RecordDigest     string       `json:"record_digest,omitempty"`
	Containment      *Containment `json:"containment,omitempty"`
	RevocationReason string       `json:"revocation_reason,omitempty"`
}

// Containment is the bounded enforcement metadata approved in D50. It
// carries neither the original reason nor case/incident data or payloads.
type Containment struct {
	ActionID  ids.UUID `json:"action_id"`
	ControlID ids.UUID `json:"control_id"`
	ScopeType string   `json:"scope_type"`
	ScopeID   string   `json:"scope_id"`
	Control   string   `json:"control"`
	Operation string   `json:"operation,omitempty"`
	Source    string   `json:"source"`
}

type rule struct{ direction, objectType, detail string }

// These are exact audit names, not suffix or prefix matches. A new kind
// requires explicit review and an accompanying replay implementation.
var kinds = map[string]rule{
	"signing_key.revoked":                {"tighten", "signing_key", ""},
	"gateway.revoked":                    {"tighten", "gateway", ""},
	"gateway.certificate_revoked":        {"tighten", "gateway_certificate", "certificate_id"},
	"access.api_key_revoked":             {"tighten", "api_key", ""},
	"access.service_account_key_revoked": {"tighten", "service_account_key", "key"},
	"access.service_account_disabled":    {"tighten", "service_account", ""},
	"access.service_account_enabled":     {"loosen", "service_account", ""},
	"access.user_disabled":               {"tighten", "user", ""},
	"access.user_enabled":                {"loosen", "user", ""},
	"access.invitation_revoked":          {"tighten", "invitation", ""},
	"package.signing_key.revoked":        {"tighten", "package_signing_key", ""},
	"authn.webauthn_suspended":           {"tighten", "webauthn", ""},
	"authn.webauthn_removed":             {"tighten", "webauthn", ""},
	"authn.session_revoked":              {"tighten", "session", ""},
	"authn.session_ended":                {"tighten", "session", ""},
	"authn.sessions_revoked":             {"tighten", "user_sessions", ""},
	"connection.sealed_revoked":          {"tighten", "sealed_credential", "version"},
	"connection.quarantined":             {"tighten", "connection", ""},
	"connection.restored":                {"loosen", "connection", ""},
	"grant.revoked":                      {"tighten", "grant", ""},
	"identity.issuer_disabled":           {"tighten", "issuer", ""},
	"response.contain":                   {"tighten", "containment_control", "control_id"},
	"agents.agent_suspended":             {"tighten", "agent", ""},
	"agents.agent_restored":              {"loosen", "agent", ""},
	"security.kill_switch_engaged":       {"tighten", "org", ""},
	"security.kill_switch_restored":      {"loosen", "org", ""},
	"org.deleted":                        {"tighten", "org", ""},
	"account.deleted":                    {"tighten", "account", ""},
}

// Rule returns the required direction and object type of a closed kind.
func Rule(kind string) (direction, objectType string, ok bool) {
	r, ok := kinds[kind]
	return r.direction, r.objectType, ok
}

// FromEntry copies only fixed fields from a successfully committed audit.
func FromEntry(entry domain.Entry, seq int64) (Event, bool, error) {
	kind := strings.TrimPrefix(entry.Kind, "audit.")
	r, ok := kinds[kind]
	if !ok {
		return Event{}, false, nil
	}
	var body struct {
		Outcome string            `json:"outcome"`
		Object  Object            `json:"object"`
		Details map[string]string `json:"details"`
	}
	if err := json.Unmarshal(entry.Body, &body); err != nil {
		return Event{}, false, fmt.Errorf("security event: invalid audit body: %w", err)
	}
	if body.Outcome != "success" {
		return Event{}, false, nil
	}
	obj := Object{Type: r.objectType, ID: body.Object.ID}
	if obj.Type == "session" {
		obj.Type = body.Object.Type
	}
	if r.detail != "" {
		obj.ID = body.Details[r.detail]
		if kind == "connection.sealed_revoked" {
			obj.ID = body.Object.ID + "/" + obj.ID
		}
	}
	if obj.ID == "" {
		return Event{}, false, fmt.Errorf("security event: %s has no object id", kind)
	}
	e := Event{Timestamp: entry.OccurredAt, Org: entry.Org, LedgerSeq: seq, Kind: kind, Direction: r.direction, Object: obj, Actor: entry.Actor}
	if kind == "org.deleted" || kind == "account.deleted" {
		e.RecordDigest = body.Details["record_digest"]
	}
	if kind == "package.signing_key.revoked" {
		e.RevocationReason = body.Details["reason"]
	}
	if kind == "response.contain" {
		action, err := ids.ParseUUID(body.Details["action"])
		if err != nil {
			return Event{}, false, fmt.Errorf("security event: invalid containment action")
		}
		control, err := ids.ParseUUID(body.Details["control_id"])
		if err != nil {
			return Event{}, false, fmt.Errorf("security event: invalid containment control")
		}
		e.Containment = &Containment{ActionID: action, ControlID: control, ScopeType: body.Details["scope_type"], ScopeID: body.Details["scope"], Control: body.Details["control"], Operation: body.Details["operation"], Source: body.Details["source"]}
	}
	return e, true, nil
}

// Emit writes one structured line. The ledger chainer calls it after its
// linking transaction commits; arbitrary audit details never reach logs.
func Emit(ctx context.Context, log *slog.Logger, e Event) {
	attrs := []slog.Attr{
		slog.String("org", e.Org.String()), slog.Int64("ledger_seq", e.LedgerSeq),
		slog.String("kind", e.Kind), slog.String("direction", e.Direction),
		slog.Group("object", slog.String("type", e.Object.Type), slog.String("id", e.Object.ID)),
		slog.Group("actor", slog.String("type", e.Actor.Type), slog.String("id", e.Actor.ID)),
	}
	if e.RecordDigest != "" {
		attrs = append(attrs, slog.String("record_digest", e.RecordDigest))
	}
	if e.RevocationReason != "" {
		attrs = append(attrs, slog.String("revocation_reason", e.RevocationReason))
	}
	if c := e.Containment; c != nil {
		attrs = append(attrs, slog.Group("containment", slog.String("action_id", c.ActionID.String()), slog.String("control_id", c.ControlID.String()), slog.String("scope_type", c.ScopeType), slog.String("scope_id", c.ScopeID), slog.String("control", c.Control), slog.String("operation", c.Operation), slog.String("source", c.Source)))
	}
	if log.Enabled(ctx, slog.LevelInfo) {
		r := slog.NewRecord(e.Timestamp, slog.LevelInfo, "security_event", 0)
		r.AddAttrs(attrs...)
		_ = log.Handler().Handle(ctx, r)
	}
}
