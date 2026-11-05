// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"crypto"
	"errors"
	"log/slog"

	"github.com/riverqueue/river"

	apapp "github.com/katocxl/pantherclaw/internal/approvals/app"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/jobs"
	"github.com/katocxl/pantherclaw/internal/platform/keys"
)

// Approval reach's wiring (G0 M36 D1063..D1066): the deployment's VAPID key
// for Web Push, the digest job and the fatigue job.

var errNoVAPIDKey = errors.New("web push: no active web_push key")

// wireM36Approvals gives the notifications service the active web_push key
// (read at each send, so a rotation takes effect) and the VAPID subject:
// notifications.web_push_subject, else the public URL.
func wireM36Approvals(cfg *Config, reg *keys.Registry, notify *napp.Service) {
	if notify == nil {
		return
	}
	subject := cfg.Notifications.WebPushSubject
	if subject == "" {
		subject = cfg.Auth.PublicURL
	}
	notify.SetWebPush(func() (crypto.Signer, error) {
		ks := reg.AltKeys(keys.PurposeWebPush)
		if len(ks) == 0 || ks[0].State != keys.StateActive || !ks[0].Private.IsSet() {
			return nil, errNoVAPIDKey
		}
		return ks[0].Private.Reveal(), nil
	}, subject)
}

// registerM36ApprovalJobs registers the digest and fatigue workers and
// returns periodic with their schedules (every 5 and 15 minutes).
func registerM36ApprovalJobs(periodic []*river.PeriodicJob, reg *jobs.Registry, approvals *apapp.Service, notify *napp.Service,
	log *slog.Logger,
) ([]*river.PeriodicJob, error) {
	if notify != nil {
		if err := napp.RegisterDigests(reg, notify); err != nil {
			return nil, err
		}
		periodic = append(periodic, napp.DigestPeriodicJobs()...)
	}
	if approvals != nil {
		if err := apapp.RegisterFatigue(reg, approvals, log); err != nil {
			return nil, err
		}
		periodic = append(periodic, apapp.FatiguePeriodicJobs()...)
	}
	return periodic, nil
}
