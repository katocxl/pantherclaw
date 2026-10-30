// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// PermHostingAgent is the requirement of HostingAgentService (G0 M19 D203):
// a hosting host's agent, authenticated by its host certificate (one host,
// purpose "hosting", no org, HR-500). No role, user, service account or
// gateway ever holds it, and no host certificate reaches anything else.
const PermHostingAgent Permission = "hosting.agent"

func init() { declarableOnly = append(declarableOnly, PermHostingAgent) }
