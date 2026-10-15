// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the rules of graduated containment (G0 M10
// coordinator decisions D21–D23; F547, F552, F561, F288, HR-248, HR-249,
// HR-252): which scopes and controls exist, which requests are narrow
// enough to commit without a preview, and how a response action's status
// follows from its paths.
package domain

import (
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/authority/pipeline"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Scope types of a containment control; the pipeline matches them (D21).
const (
	ScopeAgent      = pipeline.ControlScopeAgent
	ScopeRun        = pipeline.ControlScopeRun
	ScopeGrant      = pipeline.ControlScopeGrant
	ScopeConnection = pipeline.ControlScopeConnection
	ScopeResource   = pipeline.ControlScopeResource
	ScopePrincipal  = pipeline.ControlScopePrincipal
)

// Controls (D21).
const (
	DenyAll       = pipeline.ControlDenyAll
	HoldWrites    = pipeline.ControlHoldWrites
	DenyOperation = pipeline.ControlDenyOperation
)

// Kinds of response actions (D22).
const (
	KindContain   = "CONTAIN"
	KindTerminate = "TERMINATE"
	KindRevoke    = "REVOKE"
	KindRotate    = "ROTATE"
)

// Sources of response actions.
const (
	SourceUser     = "USER"
	SourceSOAR     = "SOAR"
	SourcePlaybook = "PLAYBOOK"
)

// Status of a response action (D22, HR-249).
type Status string

// Statuses. CONFIRMED, FAILED and UNSUPPORTED are settled.
const (
	StatusRequested   Status = "REQUESTED"
	StatusPartial     Status = "PARTIAL"
	StatusConfirmed   Status = "CONFIRMED"
	StatusFailed      Status = "FAILED"
	StatusUnsupported Status = "UNSUPPORTED"
)

// Settled reports whether the status is final.
func (s Status) Settled() bool {
	return s == StatusConfirmed || s == StatusFailed || s == StatusUnsupported
}

// Path types (D22).
const (
	PathGateway    = "GATEWAY"
	PathRoute      = "ROUTE"
	PathCredential = "CREDENTIAL"
	PathInFlight   = "IN_FLIGHT"
)

// PathStatus is a path's confirmation state (D22).
type PathStatus string

// Path statuses.
const (
	PathPending     PathStatus = "PENDING"
	PathConfirmed   PathStatus = "CONFIRMED"
	PathUnresolved  PathStatus = "UNRESOLVED"
	PathFailed      PathStatus = "FAILED"
	PathUnsupported PathStatus = "UNSUPPORTED"
)

// Path is one path a response action must reach.
type Path struct {
	ID          ids.UUID
	Type        string
	SubjectType string
	SubjectID   string
	Material    bool
	Control     string
	Status      PathStatus
}

// Limits.
const (
	MaxReason    = 1000
	MaxScopeID   = 300
	MaxOperation = 200
)

// Errors of containment requests.
var (
	ErrScope     = pcerr.New(pcerr.InvalidArgument, "SCOPE_INVALID", "the scope must be an agent, run, grant, connection, resource or principal")
	ErrControl   = pcerr.New(pcerr.InvalidArgument, "CONTROL_INVALID", "the control must be DENY_ALL, HOLD_WRITES or DENY_OPERATION with its operation")
	ErrReason    = pcerr.New(pcerr.InvalidArgument, "REASON_REQUIRED", "a reason of 1 to 1000 characters is required")
	ErrResource  = pcerr.New(pcerr.InvalidArgument, "RESOURCE_INVALID", "a resource scope is <target type>:<target id>, where a trailing * matches a prefix")
	ErrPrincipal = pcerr.New(pcerr.InvalidArgument, "PRINCIPAL_INVALID", "a principal scope is user:<id> or service_account:<id>")
)

// Control is what a request asks to add.
type Control struct {
	ScopeType string
	ScopeID   string
	Control   string
	Operation string
	Reason    string
}

// Validate checks a control request's shape; the scope's subject is
// checked against the org by the use case.
func (c Control) Validate() error {
	switch c.ScopeType {
	case ScopeAgent, ScopeRun, ScopeGrant, ScopeConnection:
		if _, err := ids.ParseUUID(c.ScopeID); err != nil {
			return ErrScope
		}
	case ScopeResource:
		t, p, ok := strings.Cut(c.ScopeID, ":")
		if !ok || t == "" || p == "" || p == "*" || len(c.ScopeID) > MaxScopeID || strings.Contains(strings.TrimSuffix(p, "*"), "*") {
			return ErrResource
		}
	case ScopePrincipal:
		k, id, ok := strings.Cut(c.ScopeID, ":")
		if _, err := ids.ParseUUID(id); !ok || (k != "user" && k != "service_account") || err != nil {
			return ErrPrincipal
		}
	default:
		return ErrScope
	}
	switch c.Control {
	case DenyAll, HoldWrites:
		if c.Operation != "" {
			return ErrControl
		}
	case DenyOperation:
		if c.Operation == "" || len(c.Operation) > MaxOperation {
			return ErrControl
		}
	default:
		return ErrControl
	}
	if n := utf8.RuneCountInString(c.Reason); !utf8.ValidString(c.Reason) || n < 1 || n > MaxReason {
		return ErrReason
	}
	return nil
}

// Narrow reports whether a control commits without a preview (D23): one
// run, or one agent's DENY_ALL or HOLD_WRITES. Anything wider (a grant with
// its dependants, a connection, a resource, a principal, an operation
// across an agent) needs the matching preview digest (HR-252).
func (c Control) Narrow() bool {
	switch c.ScopeType {
	case ScopeRun:
		return true
	case ScopeAgent:
		return c.Control == DenyAll || c.Control == HoldWrites
	}
	return false
}

// StatusOf is an action's status from its paths (HR-249): FAILED when a
// material path failed, CONFIRMED only when every material path is
// confirmed, UNSUPPORTED when no material path could be reached at all,
// PARTIAL while any material path is unresolved or pending.
func StatusOf(paths []Path) Status {
	material, confirmed, unsupported := 0, 0, 0
	for _, p := range paths {
		if !p.Material {
			continue
		}
		material++
		switch p.Status {
		case PathFailed:
			return StatusFailed
		case PathConfirmed:
			confirmed++
		case PathUnsupported:
			unsupported++
		}
	}
	switch {
	case material == 0:
		return StatusRequested
	case confirmed == material:
		return StatusConfirmed
	case unsupported == material:
		return StatusUnsupported
	}
	return StatusPartial
}
