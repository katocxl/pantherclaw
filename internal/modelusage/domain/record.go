// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"time"
	"unicode/utf8"

	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
)

// UsageOperations are the model operations that leave a usage row (D825):
// the create and count operations of pc.anthropic and pc.openai (D813).
// Reading models leaves none.
var UsageOperations = map[string]bool{
	"anthropic.messages.create":       true,
	"anthropic.messages.count_tokens": true,
	"openai.chat.create":              true,
	"openai.responses.create":         true,
}

// Record is one model call's usage row (D825), written in the transaction
// that records the call's outcome. It holds metadata and counts only, never
// a prompt or a reply (HR-695). An UNKNOWN outcome carries zero counts and
// Reported false. Estimate is set only when the connection has a price and
// the org is on Team or higher at write (D829).
type Record struct {
	ID            ids.UUID
	TransactionID ids.UUID
	RunID         *ids.UUID
	AgentID       *ids.UUID
	TeamID        *ids.UUID
	ConnectionID  ids.UUID
	Operation     string
	Model         string
	Outcome       Outcome
	Usage         Usage
	Estimate      *Amount
	RecordedAt    time.Time
}

// Validate checks the row fits pc.model_usage.
func (r Record) Validate() error {
	switch {
	case r.ID.IsZero() || r.TransactionID.IsZero() || r.ConnectionID.IsZero():
		return invalid("a usage row names its id, transaction and connection")
	case r.Operation == "" || utf8.RuneCountInString(r.Operation) > 256:
		return invalid("operation is 1..256 characters")
	case utf8.RuneCountInString(r.Model) > MaxModelLength:
		return invalid("model id is at most %d characters", MaxModelLength)
	case !r.Outcome.Valid():
		return invalid("outcome %q", r.Outcome)
	case r.Outcome == OutcomeUnknown && (r.Usage.Reported || r.Usage.Total() != 0):
		return invalid("an UNKNOWN call has no usage")
	}
	if err := r.Usage.Validate(); err != nil {
		return err
	}
	if r.Estimate != nil {
		if _, err := money.ParseCurrency(string(r.Estimate.Currency)); err != nil || r.Estimate.Amount.Sign() < 0 {
			return invalid("estimate")
		}
	}
	return nil
}
