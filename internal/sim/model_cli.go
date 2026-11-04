// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/model"
)

// runModel serves the fake model provider: the Anthropic Messages and OpenAI
// Chat Completions and Responses shapes, every answer SIMULATED (G0 M29 D826).
func runModel(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("model", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", defaultAddrs["model"], "listen address (loopback)")
	key := fs.String("key", model.DefaultKey, "the only key accepted (x-api-key, Authorization: Bearer or api-key)")
	delay := fs.Duration("stream-delay", 0, "wait this long before each stream event")
	status := fs.Int("status", 0, "answer every model call with this HTTP status, in the API's error shape")
	if err := fs.Parse(args); err != nil {
		return err
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := model.New(*key, model.Faults{StreamDelayMS: int(delay.Milliseconds()), Status: *status}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.model_listening")
}
