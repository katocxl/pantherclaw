// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	"github.com/katocxl/pantherclaw/internal/evidence/auditkind"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Opt-in prompt capture per model connection (G0 M30 D945b, founder answer
// P): off by default. Turning it on is a protected change on its own
// always-protected surface, so a second person confirms it with a security
// key whatever the CUSTODY mode, and needs Business; turning it off
// applies at once in every edition. While it is on, a capture profile that
// covers the connection keeps its requests and replies for the profile's
// retention (dispatch/capture.go).
var (
	// ErrModelCaptureEdition: turning prompt capture on needs Business.
	ErrModelCaptureEdition = pcerr.New(pcerr.FailedPrecondition, "EDITION_REQUIRED",
		"prompt capture on model connections needs the Business edition")
	// ErrModelCaptureOnCreate: a model connection is created with prompt
	// capture off; an update turns it on.
	ErrModelCaptureOnCreate = pcerr.New(pcerr.FailedPrecondition, "MODEL_CAPTURE_ON_CREATE",
		"a model connection is created with prompt capture off; turn it on with an update, which a second person confirms")
)

// captureTurnsOn reports whether a model configuration change turns prompt
// capture on.
func captureTurnsOn(before, after *ModelConfig) bool {
	return after != nil && after.CapturePrompts && (before == nil || !before.CapturePrompts)
}

// captureTurnsOff reports whether a model configuration change turns prompt
// capture off.
func captureTurnsOff(before, after *ModelConfig) bool {
	return before != nil && before.CapturePrompts && after != nil && !after.CapturePrompts
}

// checkModelCapture refuses turning prompt capture on unless the edition is
// Business or above; without an edition source it refuses (fail closed).
func (s *Service) checkModelCapture(ctx context.Context, before, after *ModelConfig) error {
	if !captureTurnsOn(before, after) {
		return nil
	}
	if s.ents == nil {
		return ErrModelCaptureEdition
	}
	e, err := s.ents.Current(ctx)
	if err != nil {
		return err
	}
	if !e.ModelPromptCapture() {
		return ErrModelCaptureEdition
	}
	return nil
}

// recordModelCapture records prompt capture turned on or off on a
// connection, in the transaction that applies it.
func recordModelCapture(ctx context.Context, tx db.TenantTx, c actor, conn ids.UUID, before, after *ModelConfig) error {
	var name string
	switch {
	case captureTurnsOn(before, after):
		name = auditkind.ModelCaptureEnabled
	case captureTurnsOff(before, after):
		name = auditkind.ModelCaptureDisabled
	default:
		return nil
	}
	_, err := audit.Record(ctx, tx, audit.Event{
		Name: name, Actor: c.Audit, Outcome: audit.Success, Object: &audit.Object{Type: "connection", ID: conn.String()},
	})
	return err
}
