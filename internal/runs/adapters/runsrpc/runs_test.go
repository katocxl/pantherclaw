// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package runsrpc

import (
	"slices"
	"testing"

	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/runs/app"
)

// TestD670_ARunReadsItsPrincipalSourceAndOperations: an ID-JAG run reads
// PRINCIPAL_SOURCE_ID_JAG and the operations it is narrowed to; the other
// stored sources keep their values, and a run without operations reads the
// whole grant (none listed).
func TestD670_ARunReadsItsPrincipalSourceAndOperations(t *testing.T) {
	for source, want := range map[string]pantherclawv1.PrincipalSource{
		app.SourceLauncher:     pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_LAUNCHER,
		app.SourceSubjectToken: pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_SUBJECT_TOKEN,
		app.SourceParentRun:    pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_PARENT_RUN,
		app.SourceIDJAG:        pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_ID_JAG,
	} {
		if got := RunProto(app.Run{ID: ids.NewV7(), PrincipalSource: source}).GetPrincipalSource(); got != want {
			t.Errorf("source %q reads %v, want %v", source, got, want)
		}
	}
	ops := []string{"payments.refund.create", "payments.refund.read"}
	r := RunProto(app.Run{ID: ids.NewV7(), PrincipalSource: app.SourceIDJAG, ScopeOperations: ops})
	if r.GetPrincipalSource() != pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_ID_JAG || !slices.Equal(r.GetScopeOperations(), ops) {
		t.Fatalf("ID-JAG run reads %v %v, want PRINCIPAL_SOURCE_ID_JAG %v", r.GetPrincipalSource(), r.GetScopeOperations(), ops)
	}
	if whole := RunProto(app.Run{ID: ids.NewV7(), PrincipalSource: app.SourceLauncher}); len(whole.GetScopeOperations()) != 0 {
		t.Fatalf("a run on its whole grant lists operations %v", whole.GetScopeOperations())
	}
}
