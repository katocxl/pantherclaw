// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package automationctx carries an automation's attribution through a
// context (G0 M11 part 2 D8, HR-274): every grant, run, launch, case,
// containment action, delivery and audit record made under it names the
// automation, version, execution and trigger. It imports only ids.
package automationctx

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Ref names the automation work a context acts for.
type Ref struct {
	Automation ids.UUID
	Version    ids.UUID
	Execution  ids.UUID
	Trigger    ids.UUID
}

// IsZero reports whether no automation is named.
func (r Ref) IsZero() bool { return r.Automation.IsZero() }

type key struct{}

// With returns ctx carrying r. A zero Ref leaves ctx unchanged.
func With(ctx context.Context, r Ref) context.Context {
	if r.IsZero() {
		return ctx
	}
	return context.WithValue(ctx, key{}, r)
}

// From returns the Ref ctx carries.
func From(ctx context.Context) (Ref, bool) {
	r, ok := ctx.Value(key{}).(Ref)
	return r, ok && !r.IsZero()
}

// Detail keys every record made under a Ref carries.
const (
	DetailAutomation = "automation"
	DetailVersion    = "version"
	DetailExecution  = "execution"
	DetailTrigger    = "trigger"
)

// MaxDetails is how many detail keys Details adds at most; their values
// are ids (36 bytes). Record reserves them beyond its callers' limit
// (D102 T5).
const MaxDetails = 4

// Details returns the attribution details of ctx (nil when none). Unset
// ids are left out.
func Details(ctx context.Context) map[string]string {
	r, ok := From(ctx)
	if !ok {
		return nil
	}
	out := map[string]string{DetailAutomation: r.Automation.String()}
	for k, v := range map[string]ids.UUID{DetailVersion: r.Version, DetailExecution: r.Execution, DetailTrigger: r.Trigger} {
		if !v.IsZero() {
			out[k] = v.String()
		}
	}
	return out
}

// Annotate adds the attribution details of ctx to details, never
// overwriting a key already present, and returns it (allocating when nil).
func Annotate(ctx context.Context, details map[string]string) map[string]string {
	d := Details(ctx)
	if d == nil {
		return details
	}
	if details == nil {
		details = make(map[string]string, len(d))
	}
	for k, v := range d {
		if _, ok := details[k]; !ok {
			details[k] = v
		}
	}
	return details
}
