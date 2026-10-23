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
			if kind == "org.deleted" || kind == "account.deleted" || kind == "org.deletion_started" {
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
