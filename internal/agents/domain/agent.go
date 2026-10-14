// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package domain holds the agent inventory's pure rules (Badge; F016, F020,
// F023, F024, F034, F574, F624; G0 M3): the lifecycle state machine, the
// accountable details a claimed agent needs, the execution context that caps
// an agent's attestation level, and the change kinds of its history. An
// agent is found by id only: a name binds nothing (HR-147). Nothing here
// grants authority.
package domain

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
)

// Limits shared with the schema (migrations/00017_agents.sql).
const (
	MaxNameLen    = 200
	MaxPurposeLen = 2000
	MaxReasonLen  = 1000
)

var (
	// ErrInvalid reports invalid agent details.
	ErrInvalid = errors.New("agents: invalid")
	// ErrContextImmutable reports an attempt to change an agent's execution
	// context, which is fixed when it is claimed (G0 M3 constraint 16).
	ErrContextImmutable = errors.New("agents: execution context is fixed for the agent's life")
	// ErrNotDiscovered reports a claim of an agent that is not discovered.
	ErrNotDiscovered = errors.New("agents: only a discovered agent can be claimed")
	// ErrRetired reports a change to a retired agent.
	ErrRetired = errors.New("agents: agent is retired")
)

// ExecutionContext is where an agent's instances run.
type ExecutionContext string

// Execution contexts.
const (
	ContextDesktop    ExecutionContext = "desktop"
	ContextCI         ExecutionContext = "ci"
	ContextKubernetes ExecutionContext = "kubernetes"
	ContextService    ExecutionContext = "service"
)

// Valid reports whether c is a known execution context.
func (c ExecutionContext) Valid() bool {
	switch c {
	case ContextDesktop, ContextCI, ContextKubernetes, ContextService:
		return true
	}
	return false
}

// MaxAttestationLevel is the highest PAP/1 attestation level an instance of
// an agent in context c can hold. Desktop workloads keep their keys in an
// OS key store that same-user malware can read, so they are capped at L1
// whatever they present (HR-092, ADR-0013).
func (c ExecutionContext) MaxAttestationLevel() int {
	if c == ContextDesktop {
		return 1
	}
	return 2
}

// Details are the accountable details of a claimed agent (F016, F574).
type Details struct {
	Name          string
	Purpose       string
	TeamID        ids.UUID
	EnvironmentID ids.UUID
	OwnerUserID   ids.UUID
	// BackupOwnerUserID is optional (zero when absent).
	BackupOwnerUserID ids.UUID
	Context           ExecutionContext
	// RangeAgent marks an agent of the adversarial range (G0 M12, HR-220):
	// set at creation, never changed.
	RangeAgent bool
}

// Validate checks the details a claimed agent needs.
func (d Details) Validate() error {
	var errs []error
	if err := ValidateName(d.Name); err != nil {
		errs = append(errs, err)
	}
	if err := ValidatePurpose(d.Purpose); err != nil {
		errs = append(errs, err)
	}
	if d.TeamID.IsZero() || d.EnvironmentID.IsZero() || d.OwnerUserID.IsZero() {
		errs = append(errs, fmt.Errorf("%w: team, environment and owner are required", ErrInvalid))
	}
	if !d.BackupOwnerUserID.IsZero() && d.BackupOwnerUserID == d.OwnerUserID {
		errs = append(errs, fmt.Errorf("%w: the backup owner must differ from the owner", ErrInvalid))
	}
	if !d.Context.Valid() {
		errs = append(errs, fmt.Errorf("%w: execution context %q", ErrInvalid, d.Context))
	}
	return errors.Join(errs...)
}

// ValidateName checks a display name. Names are labels for people; they
// are never unique and never bind identity (F034).
func ValidateName(s string) error {
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > MaxNameLen || !printable(s) {
		return fmt.Errorf("%w: name must be 1-%d printable characters", ErrInvalid, MaxNameLen)
	}
	return nil
}

// ValidatePurpose checks a purpose text.
func ValidatePurpose(s string) error {
	if utf8.RuneCountInString(s) > MaxPurposeLen || !printable(s) {
		return fmt.Errorf("%w: purpose must be at most %d printable characters", ErrInvalid, MaxPurposeLen)
	}
	return nil
}

// ValidateReason checks a reason given for a change (required).
func ValidateReason(s string) error {
	if strings.TrimSpace(s) == "" || utf8.RuneCountInString(s) > MaxReasonLen || !printable(s) {
		return fmt.Errorf("%w: a reason of 1-%d printable characters is required", ErrInvalid, MaxReasonLen)
	}
	return nil
}

// printable rejects invalid UTF-8, control characters other than newline
// and tab, and bidirectional controls, which could make text shown to
// owners and approvers say something else (HR-102).
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		switch {
		case r == '\n' || r == '\t':
		case r < 0x20 || r == 0x7f || (r >= 0x80 && r < 0xa0):
			return false
		case r == 0x061c || r == 0x200e || r == 0x200f || (r >= 0x202a && r <= 0x202e) || (r >= 0x2066 && r <= 0x2069):
			return false
		}
	}
	return true
}
