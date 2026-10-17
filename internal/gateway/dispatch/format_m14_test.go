// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package dispatch

import (
	"testing"

	defs "github.com/katocxl/pantherclaw/internal/definitions/domain"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// TestM14_SuccessCheck: a 2xx answer must carry the success value the
// definition names; otherwise the outcome is FAILED with the answer's own
// error string as a sanitized code, or target_answer_failed (G0 M14 D8).
func TestM14_SuccessCheck(t *testing.T) {
	d := &defs.Definition{Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{Success: &defs.SuccessCheck{Field: "ok", Equals: true}}}}
	accepted := pb.Outcome_OUTCOME_ACCEPTED
	for body, want := range map[string]string{
		`{"ok":true,"ts":"1"}`:                     "",
		`{"ok":false,"error":"channel_not_found"}`: "channel_not_found",
		`{"ok":false,"error":"Not In Channel!"}`:   "not_in_channel",
		`{"ok":false}`:                             CodeAnswerFailed,
		`{"ok":"true"}`:                            CodeAnswerFailed,
		`{"error":"invalid_auth"}`:                 "invalid_auth",
		`not json`:                                 CodeAnswerFailed,
		`{"ok":false,"error":""}`:                  CodeAnswerFailed,
	} {
		o, class, code := checkSuccess(d, accepted, []byte(body))
		if code != want || (want == "") != (o == accepted) || (want != "" && class != ToolFailed) {
			t.Errorf("%s: %s %s %q", body, o, class, code)
		}
	}
	if o, _, _ := checkSuccess(d, pb.Outcome_OUTCOME_FAILED, []byte(`{"ok":true}`)); o != pb.Outcome_OUTCOME_FAILED {
		t.Error("a refused answer became accepted")
	}
	if o, _, _ := checkSuccess(&defs.Definition{Dispatch: &defs.Dispatch{HTTP: &defs.HTTPDispatch{}}}, accepted, []byte(`{}`)); o != accepted {
		t.Error("no success check")
	}
	if got := sanitizeCode(string(make([]byte, 100)) + "x"); len(got) > 64 {
		t.Errorf("long code %q", got)
	}
}
