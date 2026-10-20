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

func TestSlackStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	var out, errb bytes.Buffer
	if code := Run(ctx, []string{"slack", "--addr", "127.0.0.1:0", "--external-shared", SlackApprovals}, &out, &errb); code != 0 {
		t.Fatalf("slack: %d %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "sim.slack_listening") {
		t.Fatalf("no listening log: %s", errb.String())
	}
}
