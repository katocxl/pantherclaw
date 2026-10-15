// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain_test

import (
	"errors"
	"testing"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/response/domain"
)

func TestControlValidate(t *testing.T) {
	id := ids.NewV7().String()
	for _, c := range []struct {
		c    domain.Control
		want error
	}{
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: id, Control: domain.DenyAll, Reason: "r"}, nil},
		{domain.Control{ScopeType: domain.ScopeAgent, ScopeID: id, Control: domain.DenyOperation, Operation: "x.y", Reason: "r"}, nil},
		{domain.Control{ScopeType: domain.ScopeResource, ScopeID: "github.repo:acme/*", Control: domain.HoldWrites, Reason: "r"}, nil},
		{domain.Control{ScopeType: domain.ScopePrincipal, ScopeID: "user:" + id, Control: domain.DenyAll, Reason: "r"}, nil},
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: "nope", Control: domain.DenyAll, Reason: "r"}, domain.ErrScope},
		{domain.Control{ScopeType: "org", ScopeID: id, Control: domain.DenyAll, Reason: "r"}, domain.ErrScope},
		{domain.Control{ScopeType: domain.ScopeResource, ScopeID: "github.repo:*", Control: domain.DenyAll, Reason: "r"}, domain.ErrResource},
		{domain.Control{ScopeType: domain.ScopeResource, ScopeID: "github.repo:a*b*", Control: domain.DenyAll, Reason: "r"}, domain.ErrResource},
		{domain.Control{ScopeType: domain.ScopePrincipal, ScopeID: "instance:" + id, Control: domain.DenyAll, Reason: "r"}, domain.ErrPrincipal},
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: id, Control: domain.DenyOperation, Reason: "r"}, domain.ErrControl},
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: id, Control: domain.DenyAll, Operation: "x", Reason: "r"}, domain.ErrControl},
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: id, Control: "KILL", Reason: "r"}, domain.ErrControl},
		{domain.Control{ScopeType: domain.ScopeRun, ScopeID: id, Control: domain.DenyAll}, domain.ErrReason},
	} {
		if err := c.c.Validate(); !errors.Is(err, c.want) {
			t.Errorf("%+v: %v, want %v", c.c, err, c.want)
		}
	}
}

// TestHR252_OnlyNarrowControlsSkipThePreview: one run, or one agent's
// DENY_ALL or HOLD_WRITES, is narrow; every wider scope needs the preview.
func TestHR252_OnlyNarrowControlsSkipThePreview(t *testing.T) {
	narrow := []domain.Control{
		{ScopeType: domain.ScopeRun, Control: domain.DenyAll},
		{ScopeType: domain.ScopeRun, Control: domain.DenyOperation},
		{ScopeType: domain.ScopeAgent, Control: domain.DenyAll},
		{ScopeType: domain.ScopeAgent, Control: domain.HoldWrites},
	}
	wide := []domain.Control{
		{ScopeType: domain.ScopeAgent, Control: domain.DenyOperation},
		{ScopeType: domain.ScopeGrant, Control: domain.DenyAll},
		{ScopeType: domain.ScopeConnection, Control: domain.DenyAll},
		{ScopeType: domain.ScopeResource, Control: domain.HoldWrites},
		{ScopeType: domain.ScopePrincipal, Control: domain.DenyAll},
	}
	for _, c := range narrow {
		if !c.Narrow() {
			t.Errorf("%+v is narrow", c)
		}
	}
	for _, c := range wide {
		if c.Narrow() {
			t.Errorf("%+v is wide", c)
		}
	}
}

// TestHR249_ConfirmedOnlyWhenEveryMaterialPathIs: one unresolved material
// path keeps the action PARTIAL, a failed one makes it FAILED, and
// non-material paths never decide.
func TestHR249_ConfirmedOnlyWhenEveryMaterialPathIs(t *testing.T) {
	p := func(material bool, s domain.PathStatus) domain.Path {
		return domain.Path{Material: material, Status: s}
	}
	for _, c := range []struct {
		paths []domain.Path
		want  domain.Status
	}{
		{nil, domain.StatusRequested},
		{[]domain.Path{p(true, domain.PathConfirmed)}, domain.StatusConfirmed},
		{[]domain.Path{p(true, domain.PathConfirmed), p(false, domain.PathUnresolved)}, domain.StatusConfirmed},
		{[]domain.Path{p(true, domain.PathConfirmed), p(true, domain.PathUnresolved)}, domain.StatusPartial},
		{[]domain.Path{p(true, domain.PathConfirmed), p(true, domain.PathPending)}, domain.StatusPartial},
		{[]domain.Path{p(true, domain.PathConfirmed), p(true, domain.PathUnsupported)}, domain.StatusPartial},
		{[]domain.Path{p(true, domain.PathUnsupported)}, domain.StatusUnsupported},
		{[]domain.Path{p(true, domain.PathConfirmed), p(true, domain.PathFailed)}, domain.StatusFailed},
	} {
		if got := domain.StatusOf(c.paths); got != c.want {
			t.Errorf("%+v: %s, want %s", c.paths, got, c.want)
		}
	}
}
