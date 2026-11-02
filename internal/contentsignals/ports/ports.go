// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is the content classifier port (G0 M27 D507).
package ports

import (
	"context"

	"github.com/katocxl/pantherclaw/internal/contentsignals/domain"
)

// Surface is what a scanned body is.
type Surface string

// Surfaces.
const (
	// SurfaceResult is a tool result, after the action ran.
	SurfaceResult Surface = "result"
	// SurfaceOutbound is an outbound payload, before the decision.
	SurfaceOutbound Surface = "outbound"
)

// Input is one bounded body. It lives for the call: a classifier keeps none
// of it (HR-649).
type Input struct {
	Surface Surface
	// Location is where Content sits, such as arg or body.
	Location string
	// Content is at most domain.MaxBody bytes, after secret-echo redaction.
	Content []byte
}

// ContentClassifier flags a body by kind and location, never by value. An
// error means it could not look: the caller makes that a scan_incomplete
// (D512, HR-650), so a classifier never has to decide what failure means.
type ContentClassifier interface {
	Classify(ctx context.Context, in Input) ([]domain.Finding, error)
}
