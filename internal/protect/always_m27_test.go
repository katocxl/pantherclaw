// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package protect_test

import (
	"context"
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/protect"
	tenancy "github.com/katocxl/pantherclaw/internal/tenancy/app"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// TestHR652_LeavingActiveIsAlwaysProtected: the content signal mode surface
// always waits for a second person, needs content.manage, and fails closed
// without a Gate (D512).
//
// Covers: F936
func TestHR652_LeavingActiveIsAlwaysProtected(t *testing.T) {
	s := protect.SurfaceContentSignalMode
	if s != "content.signals.mode" || !s.AlwaysProtected() || s.Permission() != td.PermContentManage {
		t.Fatalf("%s: always %v, permission %s", s, s.AlwaysProtected(), s.Permission())
	}
	applied := false
	var g *protect.Gate
	held, err := g.Hold(context.Background(), db.TenantTx{}, tenancy.Caller{}, protect.Change{
		Category: protect.ToolMeaning, Surface: s, Subject: "mode", Widening: []string{"content_signal_mode"},
	}, func(context.Context) error { applied = true; return nil })
	if !errors.Is(err, protect.ErrUnavailable) || held != nil || applied {
		t.Fatalf("without a Gate: %v %v applied %v", held, err, applied)
	}
}
