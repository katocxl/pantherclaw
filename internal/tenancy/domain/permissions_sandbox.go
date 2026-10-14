// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Sandbox permissions (G0 M9 track B). sandbox.run opens a containment
// sandbox session for an agent in scope, submits its signed probe reports
// and ends it. A person or a service account may hold it, and is named in
// the evidence; admitting the session's instance still needs a person
// holding agent.admit (HR-094), or an L2 auto-admission policy.
const PermSandboxRun Permission = "sandbox.run"
