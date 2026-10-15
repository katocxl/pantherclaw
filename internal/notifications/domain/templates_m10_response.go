// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m10ResponseTemplates are the containment notification types (G0 M10 D7,
// D22, D24; HR-249, HR-250). They render ids and fixed status words, never
// a request's reason, which is free text (HR-158).
var m10ResponseTemplates = []Template{
	{
		Type: "response.containment_partial", Severity: Warning, Params: []string{"action", "status"},
		Title: "Containment is only partly confirmed",
		Body: "Response action {action} is {status}: at least one path it must reach is not confirmed yet, such as a " +
			"gateway that was not sent the change, a bypass route or an agent-held credential. Open the action to see " +
			"which paths are still open.",
		Link: "/containment",
	},
	{
		Type: "response.containment_failed", Severity: Critical, Params: []string{"action", "status"},
		Title: "Containment failed",
		Body: "Response action {action} is {status}: a path it had to reach could not be confirmed. New access may " +
			"still be possible there. Open the action, fix or revoke what did not confirm, and contain again.",
		Link: "/containment",
	},
	{
		Type: "response.restoration_ready", Severity: Info, Params: []string{"plan", "stage"},
		Title: "A restoration stage is ready for review",
		Body: "Restoration plan {plan} passed the test actions of stage {stage}. Review the results before " +
			"widening the restoration.",
		Link: "/containment",
	},
}

func init() { templates = append(templates, m10ResponseTemplates...) }
