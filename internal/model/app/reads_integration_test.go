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
	"github.com/katocxl/pantherclaw/internal/platform/page"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR554_DraftAndUsageReadsReturnNoPromptsOrResponses: the reads give the
// mark and the counts, never the person's text or the model's output: no
// such field exists, and neither is in what comes back. They sit behind the
// same gate as drafting, and a draft reads only for who may read its kind.
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

	f.svc.Editions = &edition{billing.Team}
	if _, _, err := f.svc.ListDrafts(f.author(), page.Request{Size: 10}); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("drafts below Business: %v", err)
	}
	if _, err := f.svc.Usage(f.admin(), time.Now()); !errors.Is(err, app.ErrEdition) {
		t.Fatalf("usage below Business: %v", err)
	}
}
