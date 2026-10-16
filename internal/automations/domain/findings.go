// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"context"
	"time"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Severity of a validation finding (D4). VALIDATED needs zero errors.
type Severity string

// Severities.
const (
	SeverityError   Severity = "ERROR"
	SeverityWarning Severity = "WARNING"
)

// Finding is one validation result (D4). Path is a JSON Pointer into the
// definition.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	Path     string   `json:"path"`
	Message  string   `json:"message"`
	Example  string   `json:"example,omitzero"`
}

// Finding codes (D4).
const (
	CodeOwnerMissing             = "OWNER_MISSING"
	CodeOwnerNotActivePerson     = "OWNER_NOT_ACTIVE_PERSON"
	CodeCeilingMissing           = "CEILING_MISSING"
	CodeCeilingUnbounded         = "CEILING_UNBOUNDED"
	CodeDeadlineMissing          = "DEADLINE_MISSING"
	CodeTerminalMissing          = "TERMINAL_MISSING"
	CodeCompletionRequestOnly    = "COMPLETION_REQUEST_ONLY"
	CodeIrreversibleUnreconciled = "IRREVERSIBLE_UNRECONCILED"
	CodeGateNoApprover           = "GATE_NO_APPROVER"
	CodeLoopPossible             = "LOOP_POSSIBLE"
	CodeUnsupportedCapability    = "UNSUPPORTED_CAPABILITY"
	CodeParamUndeclared          = "PARAM_UNDECLARED"
	CodeParamUnbounded           = "PARAM_UNBOUNDED"
	CodeTemplateField            = "TEMPLATE_FIELD"
	CodeReviewDate               = "REVIEW_DATE"
	CodeLimitRange               = "LIMIT_RANGE"
	CodePrincipalInvalid         = "PRINCIPAL_INVALID"
	CodeDestinationInvalid       = "DESTINATION_INVALID"
	CodePrefixIrreversible       = "CEILING_PREFIX_IRREVERSIBLE"
)

// HasErrors reports whether any finding is an error.
func HasErrors(fs []Finding) bool {
	for _, f := range fs {
		if f.Severity == SeverityError {
			return true
		}
	}
	return false
}

// OperationInfo is what validation needs about an operation.
type OperationInfo struct {
	Known          bool
	Irreversible   bool
	ConsumesBudget bool
	// IrreversibleUnder are, for a prefix "x.*", the known irreversible
	// operations it covers (D91 K4).
	IrreversibleUnder []string
}

// ValidationEnv supplies the lookups Validate needs (D4). Implementations
// read the org's current state; a nil-able lookup error is reported as a
// finding, never ignored.
type ValidationEnv interface {
	// Now is the validation time (review dates are checked against it).
	Now() time.Time
	// Owner is the automation's current owner, from its row (D68); zero
	// when it has none.
	Owner() ids.UUID
	// OwnerActivePerson reports whether the user is an active person of
	// the org.
	OwnerActivePerson(ctx context.Context, user ids.UUID) (bool, error)
	// AgentGrantable reports whether the agent exists and can receive
	// authority.
	AgentGrantable(ctx context.Context, agent ids.UUID) (bool, error)
	// Operation describes an operation (exact name) or, for a prefix
	// "x.*", the widest of the operations it covers.
	Operation(ctx context.Context, op string) (OperationInfo, error)
	// DestinationActive reports whether an automation destination is
	// ACTIVE and serves the purpose.
	DestinationActive(ctx context.Context, destination ids.UUID, purpose string) (bool, error)
	// EligibleApprovers counts the people who could decide a gate.
	// An exclusion of PRINCIPAL removes principal (zero: the automation's
	// own identity); CONFIRMERS removes the most the enabling can have.
	EligibleApprovers(ctx context.Context, g GateWith, owner, principal ids.UUID) (int, error)
	// Edition reports whether the org's edition includes e.
	Edition(e Edition) bool
}
