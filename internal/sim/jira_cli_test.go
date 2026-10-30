// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

func TestJiraStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"jira", "--addr", "127.0.0.1:0", "--customer-visible", JiraOperations}, &out, &errb); code != 0 {
		t.Fatalf("jira: %d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "sim.jira_listening") {
		t.Fatalf("no listening log: %s", errb.String())
	}
}
