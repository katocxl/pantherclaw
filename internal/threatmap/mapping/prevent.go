// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package mapping holds PantherClaw's own threat-map tables (G0 M28 D710,
// D714): the Prevent controls, the kinds of behavior and content signals,
// the techniques outside PantherClaw and those inside an agent platform's
// reach that PantherClaw ships no control for. Pure data; it imports only
// the catalog. A mapping says "this control acts on this technique when
// an AI agent carries it out through PantherClaw".
package mapping

import "slices"

// Surface is where a Prevent control acts (D714).
type Surface string

// Surfaces (closed).
const (
	SurfaceAuthority  Surface = "AUTHORITY"
	SurfaceGateway    Surface = "GATEWAY"
	SurfaceSandbox    Surface = "SANDBOX"
	SurfaceCredential Surface = "CREDENTIAL"
)

// Surfaces lists every Surface.
func Surfaces() []Surface {
	return []Surface{SurfaceAuthority, SurfaceGateway, SurfaceSandbox, SurfaceCredential}
}

// Valid reports whether s is a listed Surface.
func (s Surface) Valid() bool { return slices.Contains(Surfaces(), s) }

// Requirement is what must hold for a Prevent control to act (D714).
type Requirement string

// Requirements (closed). A control that needs anything else is a question
// for the coordinator, never a new value here.
const (
	// RequiresAlways: the control is part of every decision.
	RequiresAlways Requirement = "ALWAYS"
	// RequiresContentSignalsActive: content signals mode ACTIVE and the
	// edition's ContentSignals().
	RequiresContentSignalsActive Requirement = "CONTENT_SIGNALS_ACTIVE"
	// RequiresMCPCatalogEnforcing: the M24 MCP catalog enforcement is on.
	RequiresMCPCatalogEnforcing Requirement = "MCP_CATALOG_ENFORCING"
)

// Requirements lists every Requirement.
func Requirements() []Requirement {
	return []Requirement{RequiresAlways, RequiresContentSignalsActive, RequiresMCPCatalogEnforcing}
}

// Valid reports whether r is a listed Requirement.
func (r Requirement) Valid() bool { return slices.Contains(Requirements(), r) }

// PreventControl is one PantherClaw control that refuses or holds an act
// carrying out the techniques it lists (D714).
type PreventControl struct {
	// ID is "prevent.<slug>".
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Surface Surface `json:"surface"`
	// ReasonCodes are the decisive pc.transactions.reason_code values that
	// are this control's refusals and holds.
	ReasonCodes []string `json:"reason_codes"`
	// HR are the hardening rules (HR-###) that state the control.
	HR         []string    `json:"hr"`
	Requires   Requirement `json:"requires"`
	Techniques []string    `json:"techniques"`
	// Why gives each technique one line that cites its id.
	Why map[string]string `json:"why"`
}

// Prevent is every Prevent control (D714).
var Prevent = []PreventControl{}
