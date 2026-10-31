// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package ecsfacts

import "testing"

// TestHR160_AControllerIsReadNeverAssumed: the fact is the controller the
// answer names; anything else is unread, never ECS (D284).
// Covers: HR-160, HR-191
func TestHR160_AControllerIsReadNeverAssumed(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   string
		want   any
	}{
		"ecs":         {200, `{"services":[{"deploymentController":{"type":"ECS"}}]}`, "ECS"},
		"code deploy": {200, `{"services":[{"deploymentController":{"type":"CODE_DEPLOY"}}]}`, "CODE_DEPLOY"},
		"no name":     {200, `{"services":[{"serviceName":"web"}]}`, nil},
		"no service":  {200, `{"services":[],"failures":[{"reason":"MISSING"}]}`, nil},
		"a bad name":  {200, `{"services":[{"deploymentController":{"type":"ecs x"}}]}`, nil},
		"not json":    {200, `not json`, nil},
		"refused":     {400, `{"services":[{"deploymentController":{"type":"ECS"}}]}`, nil},
	} {
		got := Parse(c.status, []byte(c.body))
		if got["type"] != c.want || (c.want == nil && got["unread"] == nil) {
			t.Errorf("%s: %v", name, got)
		}
	}
}
