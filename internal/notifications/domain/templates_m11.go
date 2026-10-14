// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m11Templates are the policy exception notification types (G0 M11.1 D14,
// HR-235), sent to the exception's owner alone. They render only names
// and fixed text, never the exception's reason (HR-158).
var m11Templates = []Template{
	{
		Type: "policy.exception_activated", Severity: Warning, Params: []string{"rule", "agent", "operations", "expires", "exception"},
		Title: "A policy exception you own is active",
		Body: "The policy rule {rule} no longer applies to the agent {agent} for {operations} until {expires}, under policy " +
			"exception {exception}, which you own. It is not extended: ask for a new one if it is still needed then, or revoke " +
			"it when it is no longer needed.",
		Link: "/policy-changes",
	},
	{
		Type: "policy.exception_expiring", Severity: Info, Params: []string{"rule", "agent", "operations", "expires", "exception"},
		Title: "A policy exception you own ends within a day",
		Body: "Policy exception {exception} ends at {expires}. From then the policy rule {rule} applies again to the agent " +
			"{agent} for {operations}. An exception is never extended: if it is still needed, ask for a new one.",
		Link: "/policy-changes",
	},
}

func init() { templates = append(templates, m11Templates...) }
