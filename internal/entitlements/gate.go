// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package entitlements

import (
	"context"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Class is what a procedure does, for the plan gate (D43).
type Class int

// Procedure classes.
const (
	// ClassUnknown is a procedure missing from the table: the gate treats
	// it as a change (fail closed).
	ClassUnknown Class = iota
	// ClassRead reads (Get, List, Search, Watch, Download, Explain …).
	ClassRead
	// ClassSafety reduces authority or settles risk: deciding or declining
	// approvals, the kill switch and containment, revocations and
	// suspensions, reconciliation, evidence export, incident and case work.
	ClassSafety
	// ClassChange is everything else.
	ClassChange
	// ClassAllow is the D9 allow list: always callable (who am I, the
	// account, the org's name, its plan and its onboarding).
	ClassAllow
)

// String returns the class name (read, safety, change, allow).
func (c Class) String() string {
	switch c {
	case ClassRead:
		return "read"
	case ClassSafety:
		return "safety"
	case ClassChange:
		return "change"
	case ClassAllow:
		return "allow"
	}
	return "unknown"
}

// ErrPlanRequired is the plan gate's refusal (HR-356).
var ErrPlanRequired = pcerr.New(pcerr.FailedPrecondition, "PLAN_REQUIRED",
	"this organization's plan does not allow this; choose a plan in Settings › Plan & billing")

// Allows reports whether a plan in status st lets a procedure of class c
// run (D43): NONE allows only the allow list; TRIALING, ACTIVE, PAST_DUE,
// COMP and DEV allow everything; LAPSED and PAUSED (and CANCELED past its
// period end, which reads as LAPSED) allow reads, safety actions and the
// allow list, never a change. Protection never depends on it: gateway and
// workload procedures are never gated (HR-357).
func Allows(st Status, c Class) bool {
	switch st {
	case StatusTrialing, StatusActive, StatusPastDue, StatusComp, StatusDev, StatusCanceled:
		return true
	case StatusLapsed, StatusPaused:
		return c == ClassRead || c == ClassSafety || c == ClassAllow
	default:
		return c == ClassAllow
	}
}

// Gate refuses org procedures the org's plan does not allow, when the
// server requires a plan (billing.require_plan).
type Gate struct {
	svc     *Service
	require bool
	class   func(procedure string) Class
}

// NewGate returns the plan gate. class maps a procedure to its class.
func NewGate(svc *Service, require bool, class func(procedure string) Class) *Gate {
	return &Gate{svc: svc, require: require, class: class}
}

// Check refuses procedure for org with ErrPlanRequired when the org's plan
// does not allow it.
func (g *Gate) Check(ctx context.Context, org ids.OrgID, procedure string) error {
	if g == nil || !g.require {
		return nil
	}
	c := g.class(procedure)
	if c == ClassAllow {
		return nil
	}
	p, err := g.svc.Plan(ctx, org)
	if err != nil {
		return err
	}
	if !Allows(p.Status, c) {
		return ErrPlanRequired
	}
	return nil
}
