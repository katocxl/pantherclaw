// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package authority

import (
	"context"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/evidence/capture"
	pantherclawv1 "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// CaptureRecorder keeps the payload captures a gateway sends with an
// outcome (G0 M7 design decision 10, HR-199); capture.Recorder implements
// it. It checks every body against an active profile itself.
type CaptureRecorder interface {
	Record(ctx context.Context, org ids.OrgID, gateway string, permit ids.UUID, bodies []capture.Body) (int, error)
}

// WithCaptures sets the recorder of payload captures; without one they are
// dropped.
func (s *Service) WithCaptures(c CaptureRecorder) *Service {
	s.captures = c
	return s
}

var captureDirections = map[pantherclawv1.CaptureDirection]capture.Direction{
	pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_REQUEST:  capture.Request,
	pantherclawv1.CaptureDirection_CAPTURE_DIRECTION_RESPONSE: capture.Response,
}

// recordCaptures keeps the captures of a recorded outcome. The outcome is
// recorded already, so a capture that cannot be kept never fails it: it is
// dropped and logged by ids only, never by content. A delegated outcome
// captures nothing (the agent performed the action itself).
func (s *Service) recordCaptures(ctx context.Context, gw Gateway, permit ids.UUID, outcome Outcome, caps []*pantherclawv1.PayloadCapture) {
	if len(caps) == 0 {
		return
	}
	if s.captures == nil || outcome == Delegated {
		s.log.InfoContext(ctx, "evidence.capture_dropped", slog.String("permit_id", permit.String()), slog.String("reason", "NOT_CAPTURED"))
		return
	}
	bodies := make([]capture.Body, 0, len(caps))
	for _, c := range caps {
		profile, err := ids.ParseUUID(c.GetProfileId())
		d, ok := captureDirections[c.GetDirection()]
		if err != nil || !ok {
			continue
		}
		bodies = append(bodies, capture.Body{Profile: profile, Direction: d, Content: c.GetContent(), Size: c.GetSize(), Truncated: c.GetTruncated()})
	}
	if _, err := s.captures.Record(ctx, gw.Org, gw.ID, permit, bodies); err != nil {
		s.log.WarnContext(ctx, "evidence.capture_failed", slog.String("permit_id", permit.String()), pclog.Err(err))
	}
}
