// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package securityevent projects the closed security ledger set into the
// bounded, machine-readable restore log (G0 M13 D31, D41; HR-383).
package securityevent

import (
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
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
// present only for D41 completion records; D56 intents use their own
// request/journal provenance. No reasons or bodies are copied.
type Event struct {
	Timestamp        time.Time    `json:"ts"`
	Org              ids.OrgID    `json:"org"`
	LedgerSeq        int64        `json:"ledger_seq"`
	Kind             string       `json:"kind"`
	Direction        string       `json:"direction"`
	Object           Object       `json:"object"`
	Actor            domain.Actor `json:"actor"`
	RequestID        ids.UUID     `json:"request_id,omitzero"`
	JournalDigest    string       `json:"journal_digest,omitempty"`
	RecordDigest     string       `json:"record_digest,omitempty"`
	Containment      *Containment `json:"containment,omitempty"`
	RevocationReason string       `json:"revocation_reason,omitempty"`
	McpServer        *McpServer   `json:"mcp_server,omitempty"`
}

// McpServer is what a revoke stopped, so a restore can bring back a server the
// backup never held (G0 M24 D278). Its name and matchers are identifiers; no
// title or note is copied.
type McpServer struct {
	Name          string `json:"name"`
	Transport     string `json:"transport"`
	PackageRef    string `json:"package_ref,omitempty"`
	URLHost       string `json:"url_host,omitempty"`
	URLPathPrefix string `json:"url_path_prefix,omitempty"`
	ImageDigest   string `json:"image_digest,omitempty"`
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
	// Server is the MCP server a revoke acted for: its controls sit on
	// connections under one action scoped to that server (G0 M24 D264).
	Server string `json:"server,omitempty"`
}

type rule struct{ direction, objectType, detail string }

// These are exact audit names, not suffix or prefix matches. A new kind
// requires explicit review and an accompanying replay implementation.
var kinds = map[string]rule{
	auditkind.SigningKeyRevoked:                {"tighten", "signing_key", ""},
	auditkind.GatewayRevoked:                    {"tighten", "gateway", ""},
	auditkind.GatewayCertificateRevoked:        {"tighten", "gateway_certificate", "certificate_id"},
	auditkind.AccessApiKeyRevoked:             {"tighten", "api_key", ""},
	auditkind.AccessServiceAccountKeyRevoked: {"tighten", "service_account_key", "key"},
	auditkind.AccessServiceAccountDisabled:    {"tighten", "service_account", ""},
	auditkind.AccessServiceAccountEnabled:     {"loosen", "service_account", ""},
	auditkind.AccessUserDisabled:               {"tighten", "user", ""},
	auditkind.AccessUserEnabled:                {"loosen", "user", ""},
	auditkind.AccessInvitationRevoked:          {"tighten", "invitation", ""},
	auditkind.PackageSigningKeyRevoked:        {"tighten", "package_signing_key", ""},
	auditkind.AuthnWebauthnSuspended:           {"tighten", "webauthn", ""},
	auditkind.AuthnWebauthnRemoved:             {"tighten", "webauthn", ""},
	auditkind.AuthnSessionRevoked:              {"tighten", "session", ""},
	auditkind.AuthnSessionEnded:                {"tighten", "session", ""},
	auditkind.AuthnSessionsRevoked:             {"tighten", "user_sessions", ""},
	auditkind.ResponseCredentialRevoked:        {"tighten", "sealed_credential", "version"},
	auditkind.ConnectionSealedRevoked:          {"tighten", "sealed_credential", "version"},
	auditkind.ConnectionQuarantined:             {"tighten", "connection", ""},
	auditkind.ConnectionRestored:                {"loosen", "connection", ""},
	auditkind.GrantRevoked:                      {"tighten", "grant", ""},
	auditkind.IdentityIssuerDisabled:           {"tighten", "issuer", ""},
	auditkind.ResponseContain:                   {"tighten", "containment_control", "control_id"},
	auditkind.McpCatalogServerRevoked:         {"tighten", "mcp_server", ""},
	auditkind.AgentsAgentSuspended:             {"tighten", "agent", ""},
	"agents.agent_restored":              {"loosen", "agent", ""},
	auditkind.SecurityKillSwitchEngaged:       {"tighten", "org", ""},
	auditkind.SecurityKillSwitchRestored:      {"loosen", "org", ""},
	auditkind.OrgDeletionStarted:               {"tighten", "org", ""},
	auditkind.OrgDeleted:                        {"tighten", "org", ""},
	auditkind.AccountDeletionStarted:           {"tighten", "account", ""},
	auditkind.AccountDeleted:                    {"tighten", "account", ""},
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
		switch kind {
		case auditkind.ResponseCredentialRevoked:
			obj.ID = body.Details["connection"] + "/" + obj.ID
		case auditkind.ConnectionSealedRevoked:
			obj.ID = body.Object.ID + "/" + obj.ID
		}
	}
	if obj.ID == "" {
		return Event{}, false, fmt.Errorf("security event: %s has no object id", kind)
	}
	e := Event{Timestamp: entry.OccurredAt, Org: entry.Org, LedgerSeq: seq, Kind: kind, Direction: r.direction, Object: obj, Actor: entry.Actor}
	if kind == auditkind.OrgDeleted || kind == auditkind.AccountDeleted {
		e.RecordDigest = body.Details["record_digest"]
	}
	if kind == auditkind.OrgDeletionStarted {
		request, err := ids.ParseUUID(body.Details["request_id"])
		if err != nil {
			return Event{}, false, fmt.Errorf("security event: invalid deletion intent request")
		}
		e.RequestID = request
		e.JournalDigest = body.Details["journal_digest"]
	}
	if kind == auditkind.AccountDeletionStarted {
		e.JournalDigest = body.Details["journal_digest"]
	}
	if kind == auditkind.PackageSigningKeyRevoked {
		e.RevocationReason = body.Details["reason"]
	}
	if kind == auditkind.ResponseContain {
		action, err := ids.ParseUUID(body.Details["action"])
		if err != nil {
			return Event{}, false, fmt.Errorf("security event: invalid containment action")
		}
		control, err := ids.ParseUUID(body.Details["control_id"])
		if err != nil {
			return Event{}, false, fmt.Errorf("security event: invalid containment control")
		}
		e.Containment = &Containment{ActionID: action, ControlID: control, ScopeType: body.Details["scope_type"], ScopeID: body.Details["scope"], Control: body.Details["control"], Operation: body.Details["operation"], Source: body.Details["source"], Server: body.Details["server"]}
	}
	if kind == auditkind.McpCatalogServerRevoked {
		e.McpServer = serverOf(body.Details)
	}
	if err := Validate(e); err != nil {
		return Event{}, false, err
	}
	return e, true, nil
}

// serverOf reads a revoke's spec; with no matcher there is none to carry.
func serverOf(d map[string]string) *McpServer {
	if d["package_ref"] == "" && d["url_host"] == "" && d["image_digest"] == "" {
		return nil
	}
	return &McpServer{
		Name: d["name"], Transport: d["transport"], PackageRef: d["package_ref"], URLHost: d["url_host"],
		URLPathPrefix: d["url_path_prefix"], ImageDigest: d["image_digest"],
	}
}

// Emit writes one structured line. The outbox worker calls it after its
// attempt transaction commits; arbitrary audit details never reach logs.
func Emit(ctx context.Context, log *slog.Logger, e Event) {
	attrs := []slog.Attr{
		slog.String("org", e.Org.String()), slog.Int64("ledger_seq", e.LedgerSeq),
		slog.String("kind", e.Kind), slog.String("direction", e.Direction),
		slog.Group("object", slog.String("type", e.Object.Type), slog.String("id", e.Object.ID)),
		slog.Group("actor", slog.String("type", e.Actor.Type), slog.String("id", e.Actor.ID)),
	}
	if !e.RequestID.IsZero() {
		attrs = append(attrs, slog.String("request_id", e.RequestID.String()))
	}
	if e.JournalDigest != "" {
		attrs = append(attrs, slog.String("journal_digest", e.JournalDigest))
	}
	if e.RecordDigest != "" {
		attrs = append(attrs, slog.String("record_digest", e.RecordDigest))
	}
	if e.RevocationReason != "" {
		attrs = append(attrs, slog.String("revocation_reason", e.RevocationReason))
	}
	if s := e.McpServer; s != nil {
		// A path can name a tenant, so the prefix stays out of the log line; the
		// record keeps it for replay (D290).
		attrs = append(attrs, slog.Group("mcp_server", slog.String("name", s.Name), slog.String("transport", s.Transport), slog.String("package_ref", s.PackageRef), slog.String("url_host", s.URLHost), slog.String("image_digest", s.ImageDigest)))
	}
	if c := e.Containment; c != nil {
		attrs = append(attrs, slog.Group("containment", slog.String("action_id", c.ActionID.String()), slog.String("control_id", c.ControlID.String()), slog.String("scope_type", c.ScopeType), slog.String("scope_id", c.ScopeID), slog.String("control", c.Control), slog.String("operation", c.Operation), slog.String("source", c.Source), slog.String("server", c.Server)))
	}
	if log.Enabled(ctx, slog.LevelInfo) {
		r := slog.NewRecord(e.Timestamp, slog.LevelInfo, "security_event", 0)
		r.AddAttrs(attrs...)
		_ = log.Handler().Handle(ctx, r)
	}
}
