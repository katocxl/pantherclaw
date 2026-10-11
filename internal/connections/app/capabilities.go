// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"maps"
	"slices"
	"strconv"

	"github.com/katocxl/pantherclaw/internal/definitions/domain"
	"github.com/katocxl/pantherclaw/internal/definitions/manifest"
	"github.com/katocxl/pantherclaw/internal/gen/dbq"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// Capability declarations (G0 M8 track C, F346–F350): what a connection
// supports follows from its kind, its access mode and the reviewed package
// it serves, never from a setting. A declaration says what the connection
// can do; coverage, which says what it was shown to do, is M9's (F356).

// Support levels of a capability (F347).
const (
	// Supported: the connection does it.
	Supported = "SUPPORTED"
	// Partial: it does it only as far as a cooperative agent or an opaque
	// server lets it (HR-024, HR-086).
	Partial = "PARTIAL"
	// Unsupported: it cannot.
	Unsupported = "UNSUPPORTED"
)

// Support is one capability's level and why.
type Support struct {
	Level, Detail string
}

// Operation is one operation a connection serves (F348).
type Operation struct {
	Operation, Summary, Route string
	// Access is the definition's access (read, write).
	Access     string
	TargetType string
	// Reversibility, and Verified: the definition declares a verifier, so
	// the effect can be observed after dispatch (M7).
	Reversibility string
	Verified      bool
	// Mode is the route's mode on the connection.
	Mode string
}

// Permission is something the connection's credential is used for, with
// the operations that need it (F349).
type Permission struct {
	Name    string
	Reasons []string
}

// Limit is something the connection does not do (F350).
type Limit struct {
	Code, Detail string
}

// Capabilities is a connection's declaration (F346).
type Capabilities struct {
	Discovery, Observation, Enforcement, Response Support
	// ResponseActions are the response controls that apply to it.
	ResponseActions []string
	Operations      []Operation
	Permissions     []Permission
	Limits          []Limit
	// Failure says how it behaves when something fails, one statement each.
	Failure []string
	// LastPassedTest is its last successful test (F350); nil when none.
	LastPassedTest *TestResult
}

// Capabilities returns a connection's capability declaration
// (connection.read).
func (s *Service) Capabilities(ctx context.Context, id ids.UUID) (Capabilities, error) {
	c, err := s.caller(ctx, td.PermConnectionRead)
	if err != nil {
		return Capabilities{}, err
	}
	var out Capabilities
	err = s.pool.InTenantTx(ctx, c.Org, func(ctx context.Context, tx db.TenantTx) error {
		q := dbq.New(tx)
		conn, err := q.GetConnection(ctx, c.Org, id)
		if db.IsNoRows(err) {
			return ErrNotFound
		} else if err != nil {
			return err
		}
		full, err := load(ctx, q, conn)
		if err != nil {
			return err
		}
		pin, err := q.PinnedPackageRaw(ctx, c.Org, conn.Package)
		if db.IsNoRows(err) {
			return ErrPackage
		} else if err != nil {
			return err
		}
		p, err := manifest.Decode(pin.Raw)
		if err != nil {
			return ErrPackage
		}
		out = Declare(full, p)
		last, ok, err := lastTest(ctx, q, c.Org, id, true)
		if ok {
			out.LastPassedTest = &last
		}
		return err
	})
	return out, err
}

// Declare is the declaration of a connection serving package p.
func Declare(c Connection, p *domain.Package) Capabilities {
	out := Capabilities{
		Discovery: Support{Supported, "Workloads that call it without being admitted are reported to the agent waitlist (HR-148)."},
		Observation: Support{Supported, "Every call is decided and recorded; a route in monitor mode records the decision " +
			"without blocking (HR-184)."},
		Response:        Support{Supported, "Quarantine, the kill switch and grant revocation stop its calls at once (HR-010)."},
		ResponseActions: []string{"quarantine", "kill_switch"},
		Failure: []string{
			"When PantherClaw cannot decide (the Authority unreachable, containment stale, a call that does not map), " +
				"nothing is dispatched (CANNOT_AUTHORIZE).",
		},
	}
	mode := func(route string) string {
		for _, r := range c.Routes {
			if r.Route == route {
				return r.Mode
			}
		}
		return c.DefaultMode
	}
	permissions := map[string][]string{}
	for i := range p.Definitions {
		d := &p.Definitions[i]
		served := servedRoutes(c.Kind, d)
		if len(served) == 0 {
			if len(d.Mappings) > 0 {
				out.Limits = append(out.Limits, Limit{
					"OPERATION_NOT_SERVED",
					d.Operation + ": a " + c.Kind + " connection cannot serve it (no " + c.Kind + " mapping or dispatch template).",
				})
			}
			continue
		}
		for _, route := range served {
			out.Operations = append(out.Operations, Operation{
				Operation: d.Operation, Summary: d.Summary, Route: route, Access: string(d.Access), TargetType: d.Target.Type,
				Reversibility: string(d.Reversibility), Verified: d.Verifier != nil, Mode: mode(route),
			})
		}
		if d.Verifier == nil && d.Access != domain.AccessRead {
			out.Limits = append(out.Limits, Limit{
				"EFFECT_UNVERIFIABLE",
				d.Operation + ": no verifier is declared, so its effect is recorded UNVERIFIABLE (M7).",
			})
		}
		name := string(d.Access) + " " + d.Target.Type
		permissions[name] = append(permissions[name], d.Operation+": "+d.Summary)
	}
	if c.AccessMode != AccessHeld && c.AccessMode != AccessTargetEnforced {
		// No credential of PantherClaw's is used for it.
		permissions = nil
	}
	for _, name := range slices.Sorted(maps.Keys(permissions)) {
		out.Permissions = append(out.Permissions, Permission{Name: name, Reasons: permissions[name]})
	}
	declareKind(&out, c)
	monitored := 0
	for _, o := range out.Operations {
		if o.Mode == ModeMonitor {
			monitored++
		}
	}
	if monitored > 0 {
		out.Enforcement.Level = Partial
		out.Enforcement.Detail += " " + strconv.Itoa(monitored) + " of " + strconv.Itoa(len(out.Operations)) +
			" routes are in monitor mode: decided and recorded, not enforced (HR-184)."
	}
	if out.Enforcement.Level != Supported {
		// PantherClaw sees, records and stops only what comes through it.
		for _, s := range []*Support{&out.Discovery, &out.Observation, &out.Response} {
			s.Level = Partial
			s.Detail += " Only for the calls that come through PantherClaw: see enforcement."
		}
	}
	return out
}

// declareKind adds what depends on the kind and the access mode.
func declareKind(out *Capabilities, c Connection) {
	timeout := strconv.Itoa(int(c.TimeoutMs))
	dispatched := []string{
		"A target that does not answer within " + timeout + " ms leaves the outcome UNKNOWN: its reservation is held, " +
			"nothing is retried automatically, and reconciliation follows (M7).",
		"Repeated UNKNOWN outcomes open the circuit, which quarantines the connection (HR-078).",
	}
	switch c.Kind {
	case KindLocal:
		out.Enforcement = Support{Partial, "The agent runs each command itself after asking the hook face: " +
			"a cooperative agent is stopped, an agent that skips the question is not (HR-024, HR-186)."}
		out.Failure = append(out.Failure, "The agent's hook or SDK blocks every mapped call when PantherClaw cannot answer (HR-200).")
		out.Limits = append(out.Limits, Limit{"COOPERATIVE", "Decisions bind only an agent that asks; coverage is PARTIAL at most."})
		return
	case KindMCP:
		out.Discovery.Detail += " The upstream server's tools are compared with their reviewed definitions; drift quarantines them (HR-081)."
		out.Enforcement = Support{Partial, "The gateway calls the remote MCP server for the agent, but what the server " +
			"does with a call is opaque: PARTIAL unless its egress is mediated (HR-086)."}
	default:
		out.Enforcement = Support{Supported, "The gateway builds and sends every request itself from the reviewed " +
			"template (HR-073, HR-075)."}
	}
	out.Failure = append(out.Failure, dispatched...)
	switch c.AccessMode {
	case AccessHeld:
		out.Enforcement.Detail += " Only the gateway holds the credential, sealed to its broker key (HR-060)."
		out.ResponseActions = append(out.ResponseActions, "revoke_credential", "rotate_credential")
	case AccessTargetEnforced:
		out.Enforcement = Support{Partial, out.Enforcement.Detail + " The target is declared to refuse a call without a single-use " +
			"action token (PAP-1 §10), which the gateway mints for its own requests and for those it hands an agent SDK (HR-201). " +
			"That is a declaration, not evidence: only a passing target_verifier test shows it (HR-210)."}
		out.Limits = append(out.Limits, Limit{"VERIFIER_NOT_SHOWN", "The target's token check is declared, not yet shown by a test."})
	case AccessAgentHeld:
		out.Enforcement = Support{Partial, out.Enforcement.Detail + " The agent holds its own credential and can call " +
			"the target directly (F416); an agent SDK asks the SDK face first (HR-201)."}
		out.Limits = append(out.Limits, Limit{"AGENT_HELD_CREDENTIAL", "The agent can bypass the gateway with its own credential."})
	case AccessNone:
		out.Enforcement = Support{Partial, out.Enforcement.Detail + " The target needs no credential, so anyone can " +
			"call it directly."}
		out.Limits = append(out.Limits, Limit{"OPEN_TARGET", "The target accepts calls that do not come through the gateway."})
	}
}
