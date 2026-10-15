// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"context"
	"strings"

	evdomain "github.com/katocxl/pantherclaw/internal/evidence/domain"
	napp "github.com/katocxl/pantherclaw/internal/notifications/app"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/reflex/alerts"
	reflexdomain "github.com/katocxl/pantherclaw/internal/reflex/domain"
)

// Fallbacks when a read port is missing (D17).
const (
	ContainmentUnknown  = "unknown"
	ExposureNotComputed = "not computed"
)

// why is the notification's "why it matters": a built-in rule's fixed
// title, or the rule id for anything else, so no org-authored text reaches
// a message (HR-158).
func why(s reflexdomain.Signal) string {
	if strings.HasPrefix(s.RuleID, "pc.") {
		return param(s.Title + ".")
	}
	if s.RuleID != "" {
		return "Rule " + param(s.RuleID) + " matched."
	}
	return "Source " + s.Source + " raised a signal."
}

// param keeps a value inside the template limits.
func param(v string) string {
	v = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, v))
	if r := []rune(v); len(r) > 200 {
		v = strings.TrimSpace(string(r[:200]))
	}
	if v == "" {
		return "-"
	}
	return v
}

func (h *Hooks) containment(ctx context.Context, tx db.TenantTx, subjects []reflexdomain.Subject) (string, error) {
	if h.Containment == nil {
		return ContainmentUnknown, nil
	}
	c, err := h.Containment.ContainmentSummary(ctx, tx, subjects)
	if err != nil || c == "" {
		return ContainmentUnknown, err
	}
	return param(c), nil
}

// notifyAlert sends reflex.alert, or reflex.page for a PAGE alert that is
// not a test (a test never pages, F616).
func (h *Hooks) notifyAlert(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal, r alerts.Raised) error {
	typ := reflexdomain.NotifyAlert
	if r.Attention == reflexdomain.AttentionPage && !s.Test {
		typ = reflexdomain.NotifyPage
	}
	c, err := h.containment(ctx, tx, s.Subjects)
	if err != nil {
		return err
	}
	rule := s.RuleID
	if rule == "" {
		rule = s.Source
	}
	_, err = h.Notify.Enqueue(ctx, tx, napp.Message{
		Org: tx.OrgID(), Type: typ, DedupeKey: typ + ":" + r.Alert.String(),
		Params: map[string]string{
			"rule": param(rule), "why": why(s), "severity": string(s.Severity), "containment": c,
			"exposure": ExposureNotComputed, "alert": r.Alert.String(),
		},
	})
	return err
}

func (h *Hooks) notifyIncident(ctx context.Context, tx db.TenantTx, s reflexdomain.Signal, incident ids.UUID) error {
	c, err := h.containment(ctx, tx, s.Subjects)
	if err != nil {
		return err
	}
	_, err = h.Notify.Enqueue(ctx, tx, napp.Message{
		Org: tx.OrgID(), Type: reflexdomain.NotifyIncident, DedupeKey: reflexdomain.NotifyIncident + ":" + incident.String(),
		Params: map[string]string{
			"incident": incident.String(), "why": why(s), "severity": string(s.Severity), "containment": c,
			"exposure": ExposureNotComputed,
		},
	})
	return err
}

// canonical marshals v as a canonical ledger body.
func canonical(v any) ([]byte, error) { return evdomain.CanonicalBody(v) }
