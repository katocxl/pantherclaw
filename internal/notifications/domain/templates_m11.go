// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// m11Templates are the policy rollout notification types (G0 M11.1, D12).
// They render names and the version only (HR-158).
var m11Templates = []Template{
	{
		Type: "policy.rollout_target_failed", Severity: Warning, Params: []string{"agent", "version"},
		Title: "A policy pilot could not reach an agent",
		Body: "The agent {agent} was decided with the published policy because the pilot's version {version} could not be " +
			"used for it. As its owner, review the agent and the rollout.",
	},
}

func init() { templates = append(templates, m11Templates...) }
