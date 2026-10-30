// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package ports is the boundary between PantherClaw and a customer's model
// provider (G0 M21 D304; F181, F304; TB13, T-234, T-235).
//
// A request carries a fixed task kind, the person's own text, the JSON schema
// of the structured form and a permission-scoped catalogue of names. It has
// no field for records, payloads, evidence or text an agent or target wrote
// (HR-542), and none for tools. What a provider returns is untrusted: it is
// only ever parsed strictly into a draft or a shown query (HR-543, HR-544).
package ports

import (
	"context"
	"encoding/json/jsontext"

	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
)

// TaskKind is what a provider is asked to draft.
type TaskKind string

// Task kinds.
const (
	TaskSearchQuery     TaskKind = "SEARCH_QUERY"
	TaskPolicyDraft     TaskKind = "POLICY_DRAFT"
	TaskAutomationDraft TaskKind = "AUTOMATION_DRAFT"
)

// Valid reports whether k is a known task kind.
func (k TaskKind) Valid() bool {
	return k == TaskSearchQuery || k == TaskPolicyDraft || k == TaskAutomationDraft
}

// MaxUserText bounds the person's text, in characters.
const MaxUserText = 2000

// Catalogue is the names a draft may use, reduced to what the person may
// read. It holds names only, never a record or a value.
type Catalogue struct {
	Entities        []string `json:"entities,omitzero"`
	OperationGroups []string `json:"operation_groups,omitzero"`
	StepKinds       []string `json:"step_kinds,omitzero"`
}

// DraftRequest is one call to a provider.
type DraftRequest struct {
	// Key is the organization's own provider key.
	Key pclog.Secret[string]
	// Model is the provider's model id.
	Model string
	Task  TaskKind
	// Text is the person's own text, at most MaxUserText characters.
	Text string
	// Schema is the closed JSON schema the output must follow.
	Schema jsontext.Value
	// Catalogue is the permission-scoped names.
	Catalogue Catalogue
}

// DraftResponse is what a provider returned. Output is unparsed and
// untrusted.
type DraftResponse struct {
	Output       []byte
	InputTokens  int
	OutputTokens int
}

// Provider drafts structured output from text. It holds no state of its own
// and never reads a record.
type Provider interface {
	Draft(ctx context.Context, req DraftRequest) (DraftResponse, error)
}

// Provider errors. Their messages are client-safe and carry nothing the
// provider said.
var (
	ErrKeyRejected = pcerr.New(pcerr.FailedPrecondition, "MODEL_KEY_REJECTED",
		"the model provider rejected the organization's key")
	ErrProviderBusy = pcerr.New(pcerr.ResourceExhausted, "MODEL_PROVIDER_BUSY",
		"the model provider is limiting requests; try again later")
	ErrProviderFailed = pcerr.New(pcerr.Unavailable, "MODEL_PROVIDER_FAILED",
		"the model provider did not answer; nothing was drafted")
	ErrRefused = pcerr.New(pcerr.FailedPrecondition, "MODEL_REFUSED",
		"the model declined to draft this; nothing was drafted")
	ErrInvalidOutput = pcerr.New(pcerr.FailedPrecondition, "MODEL_OUTPUT_INVALID",
		"the model's output was not a valid draft; nothing was drafted")
	ErrInvalidRequest = pcerr.New(pcerr.InvalidArgument, "MODEL_REQUEST_INVALID",
		"the drafting request is not valid")
)
