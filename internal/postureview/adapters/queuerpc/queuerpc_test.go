// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package queuerpc

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/postureview/domain"
)

func scoreLike(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "score") || strings.Contains(s, "rating") || strings.Contains(s, "weight")
}

func walk(t *testing.T, ms protoreflect.MessageDescriptors) {
	t.Helper()
	for i := range ms.Len() {
		m := ms.Get(i)
		for j := range m.Fields().Len() {
			f := m.Fields().Get(j)
			if scoreLike(string(f.Name())) || scoreLike(f.JSONName()) {
				t.Errorf("%s has a score field", f.FullName())
			}
			if k := f.Kind(); k == protoreflect.FloatKind || k == protoreflect.DoubleKind {
				t.Errorf("%s is a number for a finding", f.FullName())
			}
		}
		walk(t, m.Messages())
	}
}

// TestHR580_NoScoreInTheProtoOrItsJSON: no field of the queue's messages is a
// score, in the proto or its JSON (D203).
// Covers: F862
func TestHR580_NoScoreInTheProtoOrItsJSON(t *testing.T) {
	file := pb.File_pantherclaw_v1_posture_queue_proto
	if file.Messages().Len() == 0 {
		t.Fatal("no messages")
	}
	walk(t, file.Messages())

	f := domain.Finding{
		Source: domain.SourcePosture, SourceID: "id", Kind: "excessive_grant", Title: "T", Severity: domain.SeverityHigh,
		SeverityBasis: domain.BasisStated, Since: time.Now(), Fix: domain.Fix{Kind: domain.FixReviewGrant, TargetID: "grant:x", Label: "L"},
	}
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(finding(domain.Rank([]domain.Finding{f}, time.Now())[0]))
	if err != nil {
		t.Fatal(err)
	}
	if scoreLike(string(raw)) {
		t.Errorf("a score in the JSON: %s", raw)
	}
}

// TestFindingMapsEveryField: the fix, the basis and the empty ids.
// Covers: F861
func TestFindingMapsEveryField(t *testing.T) {
	f := domain.Rank([]domain.Finding{{
		Source: domain.SourceInventory, SourceID: "id", Kind: domain.KindNewTool, Severity: domain.SeverityMedium,
		SeverityBasis: domain.BasisByKind, Fix: domain.Fix{Kind: domain.FixReviewTool, TargetID: "inventory:x", Label: "L"},
	}}, time.Now())[0]
	got := finding(f)
	if got.GetSeverityBasis() != pb.PostureSeverityBasis_POSTURE_SEVERITY_BASIS_BY_KIND || got.GetFix().GetTargetId() != "inventory:x" {
		t.Errorf("%+v", got)
	}
	if got.GetAgentId() != "" || got.GetSince() != nil || len(got.GetOwasp()) == 0 {
		t.Errorf("%+v", got)
	}
}

// TestParseID: empty is no filter; anything else must be a UUID.
func TestParseID(t *testing.T) {
	if id, err := parseID(""); id != nil || err != nil {
		t.Errorf("empty: %v %v", id, err)
	}
	if _, err := parseID("not-a-uuid"); err != errBadID {
		t.Errorf("bad id: %v", err)
	}
}
