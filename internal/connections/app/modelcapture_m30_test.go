// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"errors"
	"testing"

	billing "github.com/katocxl/pantherclaw/internal/billing/domain"
	"github.com/katocxl/pantherclaw/internal/protect"
)

// TestHR716_TurningPromptCaptureOnNeedsBusinessAndASecondPerson (G0 M30
// D945b, HR-716): a model connection is created with capture off; turning
// it on needs Business (an unknown edition refuses) and is filed on the
// always-protected surface connection.model.capture, never applied at once;
// turning it off needs no edition, and each turn is recorded.
func TestHR716_TurningPromptCaptureOnNeedsBusinessAndASecondPerson(t *testing.T) {
	off, on := &ModelConfig{}, &ModelConfig{CapturePrompts: true}
	if !captureTurnsOn(off, on) || !captureTurnsOn(nil, on) || captureTurnsOn(on, on) || captureTurnsOn(on, off) {
		t.Fatal("captureTurnsOn")
	}
	if !captureTurnsOff(on, off) || captureTurnsOff(off, off) || captureTurnsOff(nil, off) {
		t.Fatal("captureTurnsOff")
	}
	ctx := context.Background()
	for _, e := range []billing.Edition{billing.Business, billing.Enterprise} {
		if err := (&Service{ents: edition(e)}).checkModelCapture(ctx, off, on); err != nil {
			t.Errorf("%s turning capture on: %v", e, err)
		}
	}
	for name, s := range map[string]*Service{
		"community":        {ents: edition(billing.Community)},
		"team":             {ents: edition(billing.Team)},
		"no edition known": {},
	} {
		if err := s.checkModelCapture(ctx, off, on); !errors.Is(err, ErrModelCaptureEdition) {
			t.Errorf("%s turning capture on: %v", name, err)
		}
		if err := s.checkModelCapture(ctx, on, off); err != nil {
			t.Errorf("%s turning capture off: %v", name, err)
		}
	}
	if !protect.SurfaceModelCapture.AlwaysProtected() {
		t.Fatal("turning prompt capture on is not always held for a second person")
	}
}
