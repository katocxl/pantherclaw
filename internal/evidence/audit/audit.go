// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package audit records platform-audit events (SB-4 "Platform audit"
// stream) in the evidence ledger, the same hash-chained mechanism as
// receipts (ADR-0009: one evidence system).
//
// Record must be called inside the transaction that makes the privileged
// change. If it fails, the caller returns the error and the whole change
// rolls back: a privileged change without its audit entry never commits
// (SB-4 failure behavior, fail closed).
package audit

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/katocxl/pantherclaw/internal/evidence/domain"
	"github.com/katocxl/pantherclaw/internal/evidence/ledger"
	"github.com/katocxl/pantherclaw/internal/platform/db"
)

// Outcome of an audited action.
type Outcome string

// Outcomes.
const (
	Success Outcome = "success"
	Failure Outcome = "failure"
	Denied  Outcome = "denied"
)

// Object is the thing the event is about.
type Object struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Event is one platform-audit record. Details carry small, non-secret
// context; never credentials, tokens or payloads.
type Event struct {
	Name       string // dotted, for example "licence.installed"; stored as kind "audit.<name>"
	Actor      domain.Actor
	Outcome    Outcome
	ReasonCode string // optional UPPER_SNAKE machine reason
	Object     *Object
	Details    map[string]string
}

// ErrInvalidEvent reports an event that cannot be recorded.
var ErrInvalidEvent = errors.New("audit: invalid event")

const (
	maxDetails     = 16
	maxDetailValue = 512
)

var (
	namePattern   = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)
	reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	keyPattern    = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	// Detail keys that suggest secrets are refused outright.
	forbiddenKeyParts = []string{"secret", "token", "password", "passphrase", "private", "credential", "cookie", "authorization", "proof"}
)

func (e Event) validate() error {
	switch {
	case !namePattern.MatchString(e.Name) || len(e.Name) > 100:
		return fmt.Errorf("%w: name must be a dotted lowercase name", ErrInvalidEvent)
	case e.Outcome != Success && e.Outcome != Failure && e.Outcome != Denied:
		return fmt.Errorf("%w: unknown outcome %q", ErrInvalidEvent, e.Outcome)
	case e.ReasonCode != "" && !reasonPattern.MatchString(e.ReasonCode):
		return fmt.Errorf("%w: reason code must be UPPER_SNAKE", ErrInvalidEvent)
	case e.Object != nil && (e.Object.Type == "" || len(e.Object.Type) > 64 || e.Object.ID == "" || len(e.Object.ID) > 256):
		return fmt.Errorf("%w: object type (1..64) and id (1..256) are required", ErrInvalidEvent)
	}
	return ValidateDetails(e.Details)
}

// ValidateDetails checks small, non-secret context the way audit details
// are checked: at most 16 lowercase keys, none suggesting a secret, values
// of at most 512 bytes. Reflex signal facts reuse it (G0 M10 D1).
func ValidateDetails(details map[string]string) error {
	if len(details) > maxDetails {
		return fmt.Errorf("%w: at most %d details", ErrInvalidEvent, maxDetails)
	}
	for k, v := range details {
		if !keyPattern.MatchString(k) {
			return fmt.Errorf("%w: detail key %q", ErrInvalidEvent, k)
		}
		for _, part := range forbiddenKeyParts {
			if strings.Contains(k, part) {
				return fmt.Errorf("%w: detail key %q suggests a secret", ErrInvalidEvent, k)
			}
		}
		if len(v) > maxDetailValue {
			return fmt.Errorf("%w: detail %q exceeds %d bytes", ErrInvalidEvent, k, maxDetailValue)
		}
	}
	return nil
}

// Record writes ev to the ledger in tx (the privileged change's transaction).
func Record(ctx context.Context, tx db.TenantTx, ev Event) (domain.Entry, error) {
	if err := ev.validate(); err != nil {
		return domain.Entry{}, err
	}
	body, err := domain.CanonicalBody(struct {
		Name       string            `json:"name"`
		Outcome    Outcome           `json:"outcome"`
		ReasonCode string            `json:"reason_code,omitempty"`
		Object     *Object           `json:"object,omitempty"`
		Details    map[string]string `json:"details,omitempty"`
	}{ev.Name, ev.Outcome, ev.ReasonCode, ev.Object, ev.Details})
	if err != nil {
		return domain.Entry{}, err
	}
	e, err := ledger.Append(ctx, tx, "audit."+ev.Name, ev.Actor, body)
	if err != nil {
		return domain.Entry{}, fmt.Errorf("audit: %w", err)
	}
	return e, nil
}
