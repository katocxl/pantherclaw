// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package app_test

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/model/app"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR554_DraftAndUsageReadsReturnNoPromptsOrResponses: the reads give the
// mark and the counts, never the person's text or the model's output: no
// such field exists, and neither is in what comes back. They need the
// edition drafting needs but not the server's switch, and a draft reads only
// for who may read its kind.
//
// Covers: F834
func TestHR554_DraftAndUsageReadsReturnNoPromptsOrResponses(t *testing.T) {
	f, _ := drafting(t)
	got, err := f.svc.DraftPolicy(f.author(), secretText)
	if err != nil {
		t.Fatal(err)
	}

	drafts, next, err := f.svc.ListDrafts(f.author(), page.Request{Size: 10})
	if err != nil || len(drafts) != 1 || next != "" || drafts[0].Version != got.Version || drafts[0].Origin != "model" {
		t.Fatalf("drafts: %+v, %q, %v", drafts, next, err)
	}
	if denied, _, err := f.svc.ListDrafts(f.as(td.KindUser, withoutPolicyRead(t)), page.Request{Size: 10}); len(denied) != 0 {
		t.Fatalf("a person who cannot read policies: %+v, %v", denied, err)
	}

	rows, err := f.svc.Usage(f.admin(), time.Now().Add(-time.Hour))
	if err != nil || len(rows) != 1 {
		t.Fatalf("usage: %+v, %v", rows, err)
	}
	if u := rows[0]; u.Calls != 1 || u.InputTokens != 10 || u.OutputTokens != 5 || u.Task == "" || u.Outcome == "" {
		t.Fatalf("usage: %+v", u)
	}
	if rows, err := f.svc.Usage(f.admin(), time.Now().Add(time.Hour)); err != nil || len(rows) != 0 {
		t.Fatalf("usage since later: %+v, %v", rows, err)
	}

	if text := fmt.Sprintf("%+v %+v", drafts, rows); strings.Contains(text, secretText) || strings.Contains(text, goodPolicy) {
		t.Fatalf("a read returned text: %s", text)
	}
	for _, m := range []protoreflect.ProtoMessage{&pb.ModelDraft{}, &pb.ModelUsageRow{}} {
		fields := m.ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			name := string(fields.Get(i).Name())
			if strings.Contains(name, "prompt") || strings.Contains(name, "response") || strings.Contains(name, "text") {
				t.Errorf("a field for text: %s", fields.Get(i).FullName())
			}
		}
	}

	// The server's switch stops calls, not the record of them (G0 M22 D88).
	f.svc.Config.Enabled = false
	if drafts, _, err := f.svc.ListDrafts(f.author(), page.Request{Size: 10}); err != nil || len(drafts) != 1 {
		t.Fatalf("drafts with drafting off: %+v, %v", drafts, err)
	}
	if rows, err := f.svc.Usage(f.admin(), time.Now().Add(-time.Hour)); err != nil || len(rows) != 1 {
		t.Fatalf("usage with drafting off: %+v, %v", rows, err)
	}
	if _, err := f.svc.DraftPolicy(f.author(), secretText); !errors.Is(err, app.ErrPlatformOff) {
		t.Fatalf("a draft with drafting off: %v", err)
	}

	for _, enabled := range []bool{true, false} {
		f.svc.Config.Enabled = enabled
		f.svc.Editions = &edition{billing.Team}
		if _, _, err := f.svc.ListDrafts(f.author(), page.Request{Size: 10}); !errors.Is(err, app.ErrEdition) {
			t.Fatalf("drafts below Business, drafting on %v: %v", enabled, err)
		}
		if _, err := f.svc.Usage(f.admin(), time.Now()); !errors.Is(err, app.ErrEdition) {
			t.Fatalf("usage below Business, drafting on %v: %v", enabled, err)
		}
	}
}

// TestHR554_AnOrgReadHolderReadsNeitherDraftsNorUsage: org.read reaches
// neither read (G0 M24 D95). A Scanner holds org.read and the scan submission
// only, so a key taken from a laptop is refused on both.
//
// Covers: F834
func TestHR554_AnOrgReadHolderReadsNeitherDraftsNorUsage(t *testing.T) {
	f, _ := drafting(t)
	if _, err := f.svc.DraftPolicy(f.author(), secretText); err != nil {
		t.Fatal(err)
	}
	scanner := f.as(td.KindServiceAccount, td.RoleScanner)
	if drafts, _, err := f.svc.ListDrafts(scanner, page.Request{Size: 10}); pcerr.CodeOf(err) != pcerr.PermissionDenied || len(drafts) != 0 {
		t.Fatalf("drafts: %+v, %v", drafts, err)
	}
	if rows, err := f.svc.Usage(scanner, time.Now().Add(-time.Hour)); pcerr.CodeOf(err) != pcerr.PermissionDenied || len(rows) != 0 {
		t.Fatalf("usage: %+v, %v", rows, err)
	}
}
