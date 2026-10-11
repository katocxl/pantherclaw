// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"flag"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/sandbox/edge"
)

// The sandbox's own containers run pclaw itself, built for Linux and
// mounted read-only (G0 M9): `sandbox edge` is the trusted sidecar, the
// agent's only route (internal/sandbox/edge). People run `pclaw sandbox
// run`, which starts them.

func init() {
	commands["sandbox edge"] = command{
		usage: "sandbox edge --config FILE   (inside a sandbox's edge container; started by pclaw sandbox run)",
		run:   sandboxEdge,
	}
}

func sandboxEdge(ctx context.Context, a *app, args []string) error {
	fs := flag.NewFlagSet("sandbox edge", flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	config := fs.String("config", "", "the edge configuration file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *config == "" || fs.NArg() != 0 {
		return errUsage
	}
	c, err := edge.ReadConfig(*config)
	if err != nil {
		return err
	}
	// The edge's log is its record of every refusal (HR-214): JSON lines on
	// stdout, which the session collects.
	return edge.Run(ctx, c, a.stdout, pclog.New(a.stdout, pclog.Options{Service: "pantherclaw-edge"}))
}
