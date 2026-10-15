// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import "encoding/json/jsontext"

// ValidationResult is what a policy validation found (M11.1 D7a, D8). The
// digests say which definitions and fact catalog it was computed with; the
// publish gate re-runs it when they no longer match.
type ValidationResult struct {
	Passed            bool      `json:"passed"`
	Findings          []Finding `json:"findings,omitzero"`
	DefinitionsDigest [32]byte  `json:"definitions_digest"`
	CatalogDigest     [32]byte  `json:"catalog_digest"`
}

// Finding severities.
const (
	SeverityError   = "ERROR"
	SeverityWarning = "WARNING"
	SeverityInfo    = "INFO"
)

// Finding is one validation finding. Example is an action (JSON) that
// shows it; SampleBased marks a finding drawn from generated samples, which
// can miss cases (ADR-0004, R-25).
type Finding struct {
	Code        string         `json:"code"`
	Severity    string         `json:"severity"`
	Detail      string         `json:"detail"`
	Rules       []string       `json:"rules,omitzero"`
	Example     jsontext.Value `json:"example,omitzero"`
	SampleBased bool           `json:"sample_based,omitzero"`
}

// TestResult is the outcome of a bundle's scenario tests and mutation gate
// (M11.1 D7, D7a; HR-044). Error carries a code such as TESTS_TOO_LARGE
// when the run was refused before completing; Passed is then false.
type TestResult struct {
	Passed            bool           `json:"passed"`
	Cases             []CaseResult   `json:"cases,omitzero"`
	Mutants           int            `json:"mutants"`
	Survivors         int            `json:"survivors"`
	Surviving         []MutantResult `json:"surviving,omitzero"`
	DefinitionsDigest [32]byte       `json:"definitions_digest"`
	CatalogDigest     [32]byte       `json:"catalog_digest"`
	Error             string         `json:"error,omitzero"`
}

// Test run error codes.
const (
	ErrTestsTooLarge = "TESTS_TOO_LARGE"
)

// CaseResult is one case's outcome: the decision and decisive reason the
// pipeline reached, the deciding rule if any, and why it failed.
type CaseResult struct {
	ID       string `json:"id"`
	Passed   bool   `json:"passed"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
	Rule     string `json:"rule,omitzero"`
	Detail   string `json:"detail,omitzero"`
}

// MutantResult names a mutant no case killed: the rule and the mutation
// (the mutated condition, or "remove rule").
type MutantResult struct {
	Rule     string `json:"rule"`
	Mutation string `json:"mutation"`
}
