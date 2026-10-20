// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package server

import (
	"context"
	"io"

	"github.com/katocxl/pantherclaw/internal/extension"
)

// cmdServe is `serve` without extensions, as the public binary runs it.
func cmdServe(ctx context.Context, args []string, stderr io.Writer, env Env, onStart started) error {
	return cmdServeWith(ctx, args, stderr, env, onStart, extension.Set{})
}
