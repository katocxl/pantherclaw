// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package main

import (
	"context"
	"errors"
)

// errNotWired is every decision's error until the gateway's face and the
// runtime run start are wired (G0 M34 D994, D995 phase 2): every
// invocation is answered with a deny.
var errNotWired = errors.New("the gateway's runtime face is not wired yet")

// startRun starts the Lambda's run (RuntimeService.StartRuntimeRun, D992).
func (ic *interceptor) startRun(context.Context, string) (string, error) {
	return "", errNotWired
}

// decide asks the gateway's face about one event and returns its
// interceptor output.
func (ic *interceptor) decide(context.Context, string, []byte) ([]byte, error) {
	return nil, errNotWired
}
