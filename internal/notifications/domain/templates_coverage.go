// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// coverageTemplates are coverage's notification types (G0 M9 track A,
// HR-212). An exclusion records a person's acceptance of a coverage gap, a
// weakening change like a connection's (HR-183), so every one is told. They render
// only names and fixed text, never the exclusion's reason (HR-158).
var coverageTemplates = []Template{
	{
		Type: "security.coverage_excluded", Severity: Warning, Params: []string{"user", "connection", "scope", "days"},
		Title: "A route was excluded from PantherClaw coverage",
		Body: "{user} excluded {scope} of the connection {connection} from coverage claims for {days} days. Review the " +
			"exclusion if you did not expect it.",
		Link: "/coverage",
	},
}

func init() { templates = append(templates, coverageTemplates...) }
