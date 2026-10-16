// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package automationctx_test

import (
	"context"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func TestAnnotate(t *testing.T) {
	if d := automationctx.Annotate(context.Background(), nil); d != nil {
		t.Errorf("no Ref: %v", d)
	}
	r := automationctx.Ref{Automation: ids.NewV7(), Version: ids.NewV7(), Execution: ids.NewV7()}
	ctx := automationctx.With(context.Background(), r)
	d := automationctx.Annotate(ctx, map[string]string{"execution": "kept"})
	if d["automation"] != r.Automation.String() || d["version"] != r.Version.String() || d["execution"] != "kept" {
		t.Errorf("details %v", d)
	}
	if _, ok := d["trigger"]; ok {
		t.Error("an unset trigger is recorded")
	}
	if got, ok := automationctx.From(automationctx.With(context.Background(), automationctx.Ref{})); ok {
		t.Errorf("a zero Ref is carried: %v", got)
	}
}
