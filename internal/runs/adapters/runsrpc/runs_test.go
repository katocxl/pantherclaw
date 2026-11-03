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
		app.SourceAutomation:   pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_AUTOMATION,
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

// storedSources are the principal sources the pc.runs check constraint
// runs_principal_source_check allows (migrations/00291_mcp_access.sql).
var storedSources = []string{
	app.SourceLauncher, app.SourceSubjectToken, app.SourceParentRun, app.SourceAutomation, app.SourceIDJAG,
}

// TestD670a_EveryStoredPrincipalSourceReadsAProtoValue: no run reads
// PRINCIPAL_SOURCE_UNSPECIFIED; each source a run can store maps to its own
// defined proto value, and the mapper knows no other source.
func TestD670a_EveryStoredPrincipalSourceReadsAProtoValue(t *testing.T) {
	seen := map[pantherclawv1.PrincipalSource]string{}
	for _, source := range storedSources {
		got := RunProto(app.Run{ID: ids.NewV7(), PrincipalSource: source}).GetPrincipalSource()
		if got == pantherclawv1.PrincipalSource_PRINCIPAL_SOURCE_UNSPECIFIED {
			t.Errorf("source %q reads PRINCIPAL_SOURCE_UNSPECIFIED", source)
			continue
		}
		if _, defined := pantherclawv1.PrincipalSource_name[int32(got)]; !defined {
			t.Errorf("source %q reads undefined value %d", source, got)
		}
		if other, dup := seen[got]; dup {
			t.Errorf("sources %q and %q both read %v", other, source, got)
		}
		seen[got] = source
	}
	if len(sourceToProto) != len(storedSources) {
		t.Errorf("the mapper knows %d sources, the database stores %d", len(sourceToProto), len(storedSources))
	}
}
