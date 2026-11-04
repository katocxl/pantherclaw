// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package modelconn

import (
	"io"
	"net/http"

	"github.com/katocxl/pantherclaw/internal/gateway/dispatch"
	"github.com/katocxl/pantherclaw/internal/modelapi"
)

// eventStreamType is the media type of a Bedrock ConverseStream answer (G0
// M31 D961).
const eventStreamType = "application/vnd.amazon.eventstream"

// bedrockError is a refusal in Bedrock's shape (G0 M31 D961).
type bedrockError struct {
	Message     string                `json:"message"`
	PantherClaw *dispatch.Explanation `json:"pantherclaw"`
}

// bedrockErrorType is the X-Amzn-ErrorType of a refusal's status: the
// exception names AWS SDKs read.
func bedrockErrorType(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "UnrecognizedClientException"
	case http.StatusForbidden:
		return "AccessDeniedException"
	case http.StatusNotFound:
		return "ResourceNotFoundException"
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType:
		return "ValidationException"
	case http.StatusServiceUnavailable:
		return "ServiceUnavailableException"
	default:
		return "InternalServerException"
	}
}

// answerStream reads an answer's usage as it passes (D818): an SSE stream,
// or a Bedrock event stream (G0 M31 D961).
type answerStream interface {
	io.Writer
	Usage() modelapi.Usage
	Complete() bool
	Errored() bool
}

// streamOf is the reader of an answer of media type mt, nil for an answer
// that is not a stream.
func streamOf(api modelapi.API, mt string) answerStream {
	switch {
	case mt == "text/event-stream":
		return modelapi.NewStream(api)
	case mt == eventStreamType && api.Bedrock():
		return modelapi.NewEventStream(api)
	}
	return nil
}
