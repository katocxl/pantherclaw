// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package promotions

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/katocxl/pantherclaw/internal/actionir"
)

// Check names, in the order a readiness lists them (D39).
const (
	CheckOwner           = "OWNER"
	CheckIdentity        = "IDENTITY"
	CheckTests           = "TESTS"
	CheckApprovals       = "APPROVALS"
	CheckCoverage        = "COVERAGE"
	CheckFailureBehavior = "FAILURE_BEHAVIOUR" //nolint:misspell // the check name D39 gives
)

// CheckNames are every check, in order.
var CheckNames = []string{CheckOwner, CheckIdentity, CheckTests, CheckApprovals, CheckCoverage, CheckFailureBehavior}

// Failure behaviors a promotion declares: what the agent's work does when
// PantherClaw cannot decide (F334).
const (
	FailClosed       = "FAIL_CLOSED"
	Queue            = "QUEUE"
	DegradeReadOnly  = "DEGRADE_READ_ONLY"
	maxOperations    = 50
	maxDetail        = 500
	maxRevokeReason  = 500
	promotionOpMaxLn = 128
)

// FailureBehaviors are the declarable failure behaviors.
var FailureBehaviors = []string{FailClosed, Queue, DegradeReadOnly}

// Check is one check of one operation: whether it passed and why.
type Check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
	// Pending marks a COVERAGE check that fails only because no coverage
	// record exists yet (D80): the operation can be promoted provisionally.
	Pending bool `json:"pending,omitzero"`
}

// Readiness is one operation's readiness in one environment: every check
// for that operation alone (never a claim about the agent as a whole).
type Readiness struct {
	Operation string
	Checks    []Check
	// Promotion is the operation's ACTIVE promotion, when there is one.
	Promotion *Promotion
}

// Ready reports whether every check passed.
func (r Readiness) Ready() bool {
	return len(r.Checks) == len(CheckNames) && !slices.ContainsFunc(r.Checks, func(c Check) bool { return !c.Passed })
}

// Provisional reports whether every check passed but COVERAGE, which is
// only pending: no coverage record exists yet (D80).
func (r Readiness) Provisional() bool {
	if len(r.Checks) != len(CheckNames) {
		return false
	}
	for _, c := range r.Checks {
		if !c.Passed && (c.Name != CheckCoverage || !c.Pending) {
			return false
		}
	}
	return !r.Ready()
}

// Failed lists the names of the checks that did not pass.
func (r Readiness) Failed() []string {
	var out []string
	for _, c := range r.Checks {
		if !c.Passed {
			out = append(out, c.Name)
		}
	}
	return out
}

var opPrefixRe = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+){0,6}\.\*$`)

// validOperation reports whether op is an exact operation or a prefix
// such as payments.*, as grants list them.
func validOperation(op string) bool {
	return len(op) <= promotionOpMaxLn && (actionir.ValidOperation(op) || opPrefixRe.MatchString(op))
}

// normalizeOperations checks, sorts and deduplicates operations.
func normalizeOperations(ops []string) ([]string, error) {
	if len(ops) == 0 || len(ops) > maxOperations {
		return nil, fmt.Errorf("name 1 to %d operations", maxOperations)
	}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if !validOperation(op) {
			return nil, fmt.Errorf("%q is neither an operation nor a prefix such as payments.*", op)
		}
		out = append(out, op)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// prefixOf returns the "x." part of an "x.*" pattern.
func prefixOf(p string) (string, bool) {
	if s, ok := strings.CutSuffix(p, "*"); ok {
		return s, true
	}
	return "", false
}

// matches reports whether pattern p matches the exact operation op.
func matches(p, op string) bool {
	if pre, ok := prefixOf(p); ok {
		return strings.HasPrefix(op, pre)
	}
	return p == op
}

// clip cuts a detail to maxDetail bytes on a character boundary.
func clip(s string) string {
	if len(s) <= maxDetail {
		return s
	}
	return strings.ToValidUTF8(s[:maxDetail-3], "") + "..."
}
