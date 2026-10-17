// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"strings"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// Codes of the M14 definition format (G0 M14 D8).
const (
	// CodeCredentialPattern: the opened credential does not match the
	// definition's credential pattern, so nothing was sent (HR-301).
	CodeCredentialPattern = "credential_pattern" //nolint:gosec // G101: an error code, not a credential
	// CodeAnswerFailed: a 2xx answer without the success value the
	// definition names, and no error code of its own.
	CodeAnswerFailed = "target_answer_failed"
)

// errCredentialPattern refuses a credential the pattern does not match.
var errCredentialPattern = errors.New("dispatch: the credential does not match the definition's pattern")

// checkSuccess applies a definition's success check to a 2xx answer (D8):
// the answer must be a JSON object whose top-level field is the boolean
// the definition names, or the outcome is FAILED, with the answer's own
// error string, sanitized, as its code (Slack's {"ok":false,"error":...}).
func checkSuccess(def *defs.Definition, outcome pb.Outcome, body []byte) (pb.Outcome, Class, string) {
	if outcome != pb.Outcome_OUTCOME_ACCEPTED || def.Dispatch == nil || def.Dispatch.HTTP == nil || def.Dispatch.HTTP.Success == nil {
		return outcome, "", ""
	}
	s := def.Dispatch.HTTP.Success
	var answer map[string]jsontext.Value
	if err := json.Unmarshal(body, &answer); err == nil {
		var got bool
		if json.Unmarshal(answer[s.Field], &got) == nil && got == s.Equals {
			return outcome, "", ""
		}
	}
	code := CodeAnswerFailed
	var e string
	if json.Unmarshal(answer["error"], &e) == nil {
		if c := sanitizeCode(e); c != "" {
			code = c
		}
	}
	return pb.Outcome_OUTCOME_FAILED, ToolFailed, code
}

// sanitizeCode is an answer's error string as a code: lower case letters,
// digits and underscores, every other byte an underscore, at most 64.
func sanitizeCode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s) && b.Len() < 64; i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '_':
			b.WriteByte(c)
		case 'A' <= c && c <= 'Z':
			b.WriteByte(c + 'a' - 'A')
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}
