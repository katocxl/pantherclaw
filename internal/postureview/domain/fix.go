// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"slices"
	"strings"
)

// remediationTargets are the records whose pages only an edition with
// posture remediation serves.
var remediationTargets = []string{"posture_finding:", "suggestion:"}

// WithoutRemediation is the fix on an edition with no posture remediation
// (D258): a fix that points at a source page stays, and one that could only
// lead to a page that refuses says so and carries no target.
func (f Fix) WithoutRemediation() Fix {
	if slices.ContainsFunc(remediationTargets, func(p string) bool { return strings.HasPrefix(f.TargetID, p) }) {
		return Fix{Kind: FixNone, Label: "Fixing this needs the Business edition", RequiresBusiness: true}
	}
	return f
}

// postureFixes are the fixes of the posture kinds. The target is the
// finding's root cause, the record its fix acts on.
var postureFixes = map[string]Fix{
	"excessive_grant":           {Kind: FixReviewGrant, Label: "Bound the grant's write authority"},
	"uncovered_path":            {Kind: FixEnforcePath, Label: "Route this path through enforcement"},
	"unowned_agent":             {Kind: FixAssignOwner, Label: "Assign the agent an owner"},
	"unsafe_delegation":         {Kind: FixReviewGrant, Label: "Stop delegating this grant over an unenforced path"},
	"stale_credential":          {Kind: FixRotateSecret, Label: "Rotate the credential"},
	"unused_authority":          {Kind: FixReviewGrant, Label: "Narrow the grant to what is used"},
	"unverified_sensitive_tool": {Kind: FixAddVerifier, Label: "Add an effect verifier"},
	"credential_overreach":      {Kind: FixNarrowScopes, Label: "Narrow the credential to what its operations need"},
	"unconfirmed_rotation":      {Kind: FixRotateSecret, Label: "Remove the old key and confirm the rotation"},
}

// PostureFix is the fix of a posture finding. Any kind without its own entry
// goes to the finding itself, so no finding is left without a fix.
func PostureFix(kind, rootCause, findingID string) Fix {
	if f, ok := postureFixes[kind]; ok {
		f.TargetID = rootCause
		return f
	}
	return Fix{Kind: FixReviewFinding, TargetID: "posture_finding:" + findingID, Label: "Review the finding"}
}
