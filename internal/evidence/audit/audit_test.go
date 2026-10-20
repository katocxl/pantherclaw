// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package audit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/katocxl/pantherclaw/internal/automations/automationctx"
	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

func valid() Event {
	return Event{
		Name: "licence.installed", Actor: domain.Actor{Type: "user", ID: "u-1"}, Outcome: Success,
		ReasonCode: "LICENCE_VALID", Object: &Object{Type: "licence", ID: "lic-1"},
		Details: map[string]string{"edition": "team"},
	}
}

func TestEventValidation(t *testing.T) {
	if err := valid().validate(); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Event){
		"flat name":    func(e *Event) { e.Name = "installed" },
		"upper name":   func(e *Event) { e.Name = "Licence.Installed" },
		"bad outcome":  func(e *Event) { e.Outcome = "ok" },
		"bad reason":   func(e *Event) { e.ReasonCode = "lower" },
		"empty object": func(e *Event) { e.Object = &Object{} },
		"secret key":   func(e *Event) { e.Details = map[string]string{"client_secret": "x"} },
		"token key":    func(e *Event) { e.Details = map[string]string{"api_token": "x"} },
		"bad key":      func(e *Event) { e.Details = map[string]string{"Bad-Key": "x"} },
		"long value":   func(e *Event) { e.Details = map[string]string{"note": strings.Repeat("x", 513)} },
		"too many":     func(e *Event) { e.Details = manyDetails(17) },
	}
	for name, mutate := range cases {
		e := valid()
		mutate(&e)
		if err := e.validate(); !errors.Is(err, ErrInvalidEvent) {
			t.Errorf("%s: accepted (err %v)", name, err)
		}
	}
}

func manyDetails(n int) map[string]string {
	m := map[string]string{}
	for i := range n {
		m["k"+strings.Repeat("a", i+1)] = "v"
	}
	return m
}

// TestHR347_BrowserSessionEventsSayAuthKind: an event recorded for a
// cookie-authenticated API call carries auth_kind=browser_session, also at
// the detail limit and under an automation; a caller's own auth_kind is
// kept; the caller's map is never changed.
func TestHR347_BrowserSessionEventsSayAuthKind(t *testing.T) {
	ctx := WithAuthKind(context.Background(), "browser_session")
	if k, ok := AuthKindFrom(ctx); !ok || k != "browser_session" {
		t.Fatalf("AuthKindFrom = %q, %v", k, ok)
	}
	ev := valid()
	ev.Details = nil
	got, err := annotated(ctx, ev)
	if err != nil || got.Details[AuthKindDetail] != "browser_session" {
		t.Fatalf("annotated = %v, %v", got.Details, err)
	}
	ev.Details = map[string]string{}
	for i := range maxDetails {
		ev.Details[fmt.Sprintf("k%02d", i)] = strings.Repeat("v", maxDetailValue)
	}
	r := automationctx.Ref{Automation: ids.NewV7(), Version: ids.NewV7(), Execution: ids.NewV7(), Trigger: ids.NewV7()}
	got, err = annotated(automationctx.With(ctx, r), ev)
	if err != nil || got.Details[AuthKindDetail] != "browser_session" || got.Details["trigger"] != r.Trigger.String() {
		t.Fatalf("maximum event: %v", err)
	}
	if len(ev.Details) != maxDetails {
		t.Error("the caller's map was changed")
	}
	ev.Details = map[string]string{AuthKindDetail: "api_key"}
	if got, err := annotated(ctx, ev); err != nil || got.Details[AuthKindDetail] != "api_key" {
		t.Errorf("caller's auth_kind: %v %v", got.Details, err)
	}
	if got, err := annotated(context.Background(), valid()); err != nil || got.Details[AuthKindDetail] != "" {
		t.Errorf("no auth kind: %v %v", got.Details, err)
	}
}

// TestAnnotationFitsAMaximumEvent: a caller's event at every detail limit
// stays valid under an automation's attribution (G0 M11 part 2 D102 T5),
// and a key contradicting it is refused (D106 D3).
func TestAnnotationFitsAMaximumEvent(t *testing.T) {
	r := automationctx.Ref{Automation: ids.NewV7(), Version: ids.NewV7(), Execution: ids.NewV7(), Trigger: ids.NewV7()}
	ctx := automationctx.With(context.Background(), r)
	ev := valid()
	ev.Details = map[string]string{}
	for i := range maxDetails {
		ev.Details[fmt.Sprintf("k%02d", i)] = strings.Repeat("v", maxDetailValue)
	}
	got, err := annotated(ctx, ev)
	if err != nil {
		t.Fatalf("a maximum event under an automation: %v", err)
	}
	if len(got.Details) != maxDetails+automationctx.MaxDetails || got.Details["trigger"] != r.Trigger.String() {
		t.Errorf("annotated %d details", len(got.Details))
	}
	if len(ev.Details) != maxDetails {
		t.Error("the caller's map was changed")
	}
	ev.Details = map[string]string{"execution": r.Execution.String()}
	if got, err := annotated(ctx, ev); err != nil || got.Details["automation"] != r.Automation.String() {
		t.Errorf("a repeated attribution: %v %v", got.Details, err)
	}
	ev.Details = map[string]string{"execution": "the caller's"}
	if _, err := annotated(ctx, ev); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("a contradicting caller key (D106 D3): %v", err)
	}
	ev.Details = map[string]string{}
	for i := range maxDetails + 1 {
		ev.Details[fmt.Sprintf("k%02d", i)] = "v"
	}
	if _, err := annotated(ctx, ev); !errors.Is(err, ErrInvalidEvent) {
		t.Errorf("17 caller details: %v", err)
	}
}
