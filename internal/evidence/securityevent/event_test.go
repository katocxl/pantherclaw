// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package securityevent

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TestHR383_ARevokeCarriesItsSpecAndNothingElse: a restore can rebuild the
// server from the record, which copies its identifiers and no free text; a
// spec is bounded and belongs to that one kind (G0 M24 D278).
func TestHR383_ARevokeCarriesItsSpecAndNothingElse(t *testing.T) {
	object := ids.NewV7().String()
	entry := func(details map[string]string) domain.Entry {
		body, err := domain.CanonicalBody(map[string]any{"outcome": "success", "object": Object{Type: "mcp_server", ID: object}, "details": details})
		if err != nil {
			t.Fatal(err)
		}
		return domain.Entry{Org: ids.New[ids.Org](), Kind: "audit.mcp.catalog.server_revoked", OccurredAt: time.Now(), Actor: domain.Actor{Type: "user", ID: ids.NewV7().String()}, Body: body}
	}
	e, ok, err := FromEntry(entry(map[string]string{
		"name": "payments", "transport": "http", "url_host": "mcp.example.test", "url_path_prefix": "/v1", "package_ref": "", "image_digest": "", "reason": "never log this free text",
	}), 1)
	if err != nil || !ok || e.McpServer == nil || e.McpServer.Name != "payments" || e.McpServer.URLHost != "mcp.example.test" || e.McpServer.URLPathPrefix != "/v1" {
		t.Fatalf("event %+v %v %v", e, ok, err)
	}
	line, err := json.Marshal(e)
	if err != nil || strings.Contains(string(line), "never log") {
		t.Fatalf("line %s %v", line, err)
	}
	if e, ok, err := FromEntry(entry(map[string]string{"name": "payments"}), 1); err != nil || !ok || e.McpServer != nil {
		t.Fatalf("no matcher: %+v %v %v", e, ok, err)
	}
	for name, change := range map[string]func(*Event){
		"bad name":      func(e *Event) { e.McpServer = &McpServer{Name: "Not A Name", Transport: "http", URLHost: "h"} },
		"bad transport": func(e *Event) { e.McpServer = &McpServer{Name: "a", Transport: "ftp", URLHost: "h"} },
		"names nothing": func(e *Event) { e.McpServer = &McpServer{Name: "a", Transport: "http"} },
		"oversized": func(e *Event) {
			e.McpServer = &McpServer{Name: "a", Transport: "http", URLHost: strings.Repeat("h", 262)}
		},
		"another kind": func(e *Event) { e.Kind, e.Object.Type = "connection.quarantined", "connection" },
	} {
		bad := e
		change(&bad)
		if Validate(bad) == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

// TestHR383_ClosedSecuritySetCopiesOnlyMachineFields proves the projection
// cannot ship the reason, account email, payload or arbitrary audit detail.
func TestHR383_ClosedSecuritySetCopiesOnlyMachineFields(t *testing.T) {
	for kind, rule := range kinds {
		t.Run(kind, func(t *testing.T) {
			object := ids.NewV7().String()
			body := map[string]any{"outcome": "success", "object": Object{Type: rule.objectType, ID: object}, "details": map[string]string{
				"reason": "never log this free text", "email": "private@example.com", "payload": "private-body", "connection": object, "certificate_id": object, "key": object, "version": "2", "record_digest": strings.Repeat("a", 64), "request_id": ids.NewV7().String(), "journal_digest": strings.Repeat("b", 64), "action": ids.NewV7().String(), "control_id": object, "scope_type": "agent", "scope": ids.NewV7().String(), "control": "DENY_ALL", "source": "PERSON",
			}}
			if kind == "package.signing_key.revoked" {
				body["details"].(map[string]string)["reason"] = "ROTATED"
			}
			if rule.objectType == "session" {
				body["object"] = Object{Type: "cli_session", ID: object}
			}
			raw, err := domain.CanonicalBody(body)
			if err != nil {
				t.Fatal(err)
			}
			at := time.Date(2026, 10, 22, 11, 0, 0, 0, time.UTC)
			entry := domain.Entry{Org: ids.New[ids.Org](), ID: ids.NewV7(), Kind: "audit." + kind, OccurredAt: at, Actor: domain.Actor{Type: "user", ID: ids.NewV7().String()}, Body: raw}
			if kind == "security.kill_switch_engaged" {
				entry.Org, _ = ids.Parse[ids.Org](object)
			}
			if kind == "org.deleted" || kind == "account.deleted" || kind == "org.deletion_started" || kind == "account.deletion_started" {
				entry.Org = ids.PlatformOrg
			}
			e, ok, err := FromEntry(entry, 7)
			if err != nil || !ok {
				t.Fatalf("projection = %+v %v %v", e, ok, err)
			}
			var output bytes.Buffer
			Emit(context.Background(), pclog.New(&output, pclog.Options{}), e)
			if strings.Count(output.String(), "\n") != 1 {
				t.Fatalf("not one line: %s", output.String())
			}
			for _, forbidden := range []string{"never log this", "private@example.com", "private-body", "payload"} {
				if strings.Contains(output.String(), forbidden) {
					t.Fatalf("leaked %s", forbidden)
				}
			}
			var decoded Event
			if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.Kind != kind || decoded.LedgerSeq != 7 || !decoded.Timestamp.Equal(at) || decoded.Direction != rule.direction {
				t.Fatalf("wrong line: %s", output.String())
			}
			stored, err := json.Marshal(e)
			if err != nil {
				t.Fatal(err)
			}
			var roundTrip Event
			if err := json.Unmarshal(stored, &roundTrip); err != nil || roundTrip.RequestID != decoded.RequestID {
				t.Fatalf("outbox and log UUID contracts differ: %s %v", stored, err)
			}
			if e.Containment != nil && (roundTrip.Containment.ActionID != decoded.Containment.ActionID || roundTrip.Containment.ControlID != decoded.Containment.ControlID || !bytes.Contains(stored, []byte(e.Containment.ActionID.String()))) {
				t.Fatal("containment UUID transport changed")
			}
		})
	}
}

func TestHR383_UnknownAndFailedEntriesEmitNothing(t *testing.T) {
	for _, test := range []struct{ kind, outcome string }{{"audit.access.api_key_created", "success"}, {"audit.access.api_key_revoked", "denied"}, {"audit.gateway.revoked", "failure"}} {
		body, _ := domain.CanonicalBody(map[string]any{"outcome": test.outcome, "object": Object{Type: "api_key", ID: ids.NewV7().String()}})
		if _, ok, err := FromEntry(domain.Entry{Kind: test.kind, Body: body}, 1); err != nil || ok {
			t.Fatalf("%s/%s: emitted=%v err=%v", test.kind, test.outcome, ok, err)
		}
	}
}

func TestHR383_MalformedMachineMetadataFailsClosed(t *testing.T) {
	for _, version := range []string{"-1", "01", "2147483648", "one"} {
		body, _ := domain.CanonicalBody(map[string]any{"outcome": "success", "object": Object{Type: "connection", ID: ids.NewV7().String()}, "details": map[string]string{"version": version}})
		entry := domain.Entry{Org: ids.New[ids.Org](), Kind: "audit.connection.sealed_revoked", OccurredAt: time.Now(), Actor: domain.Actor{Type: "user", ID: ids.NewV7().String()}, Body: body}
		if _, ok, err := FromEntry(entry, 1); err == nil || ok {
			t.Errorf("accepted credential version %q", version)
		}
	}
	body, _ := domain.CanonicalBody(map[string]any{"outcome": "success", "object": Object{Type: "package_signing_key", ID: "trusted-key"}, "details": map[string]string{"reason": "arbitrary free text"}})
	entry := domain.Entry{Org: ids.New[ids.Org](), Kind: "audit.package.signing_key.revoked", OccurredAt: time.Now(), Actor: domain.Actor{Type: "user", ID: ids.NewV7().String()}, Body: body}
	if _, ok, err := FromEntry(entry, 1); err == nil || ok {
		t.Fatal("accepted unbounded reason")
	}
}

func TestHR383_DeletionIntentsUseBoundedDistinctProvenance(t *testing.T) {
	for _, kind := range []string{"org.deletion_started", "account.deletion_started"} {
		t.Run(kind, func(t *testing.T) {
			_, typ, _ := Rule(kind)
			e := Event{Timestamp: time.Now(), Org: ids.PlatformOrg, LedgerSeq: 1, Kind: kind, Direction: "tighten", Object: Object{Type: typ, ID: ids.NewV7().String()}, Actor: domain.Actor{Type: "system", ID: "deletion"}, JournalDigest: strings.Repeat("a", 64)}
			if kind == "org.deletion_started" {
				e.RequestID = ids.NewV7()
			}
			if err := Validate(e); err != nil {
				t.Fatal(err)
			}
			for _, change := range []func(*Event){
				func(e *Event) { e.Org = ids.New[ids.Org]() },
				func(e *Event) { e.JournalDigest = "not-a-digest" },
				func(e *Event) { e.RecordDigest = strings.Repeat("b", 64) },
				func(e *Event) {
					if kind == "account.deletion_started" {
						e.RequestID = ids.NewV7()
					} else {
						e.RequestID = ids.UUID{}
					}
				},
			} {
				bad := e
				change(&bad)
				if err := Validate(bad); err == nil {
					t.Fatalf("accepted invalid intent: %+v", bad)
				}
			}
		})
	}
}

func TestHR383_IntentReadinessRejectsInvalidInputsBeforeDatabaseAccess(t *testing.T) {
	for _, test := range []struct {
		kind   string
		target ids.UUID
		digest string
	}{
		{"org.deleted", ids.NewV7(), strings.Repeat("a", 64)},
		{"unknown", ids.NewV7(), strings.Repeat("a", 64)},
		{"org.deletion_started", ids.UUID{}, strings.Repeat("a", 64)},
		{"account.deletion_started", ids.NewV7(), "not-a-digest"},
		{"account.deletion_started", ids.NewV7(), strings.Repeat("A", 64)},
	} {
		if ready, err := IntentAcknowledged(context.Background(), nil, test.kind, test.target, test.digest); err == nil || ready {
			t.Fatalf("invalid readiness accepted: %+v", test)
		}
	}
}
