// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"context"
	"encoding/json/v2"
	"log/slog"

	"github.com/katocxl/pantherclaw/internal/actionir"
	"github.com/katocxl/pantherclaw/internal/gateway/control"
)

// The secret-field refusal (G0 M33 D978, HR-747): a pc.browser form submit
// that names a password, one-time-code or payment field is refused before
// the Authority is asked anything. No policy changes it; a person submits
// that form after a takeover (D982).
const (
	// CodeBrowserSecretField: the submit has a secret field.
	CodeBrowserSecretField = "BROWSER_SECRET_FIELD"
	// BrowserSecretFieldReason is the agent-safe reason (HR-400).
	BrowserSecretFieldReason = "PantherClaw never lets an agent submit password, one-time-code or payment fields. " +
		"Ask a person to take over this tab (the PantherClaw toolbar button) and continue after."
	// localBrowserSecretField is the refusal's report code (G0 M12 style).
	localBrowserSecretField = "browser_secret_field"

	browserPackage = "pc.browser"
	browserSubmit  = "browser.form.submit"
)

// browserSecretField reports, and refuses, a pc.browser form submit whose
// secret_fields param is true. Params it cannot read are refused too: the
// mapping wrote them, so unreadable params fail closed.
func (e *Engine) browserSecretField(ctx context.Context, conn *control.Connection, a actionir.ActionIR) bool {
	if a.Definition.Package != browserPackage || a.Operation != browserSubmit {
		return false
	}
	var p struct {
		SecretFields *bool `json:"secret_fields"`
	}
	if err := json.Unmarshal(a.Params, &p); err == nil && p.SecretFields != nil && !*p.SecretFields {
		return false
	}
	e.log.WarnContext(ctx, "gateway.browser_secret_field_refused", slog.String("connection_id", conn.GetId()),
		slog.String("run_id", a.RunID), slog.String("operation", a.Operation))
	e.reportLocalRefusal(ctx, conn, localBrowserSecretField, a, RefusalDetail{})
	return true
}
