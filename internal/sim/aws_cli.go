// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/aws"
)

// runAWS serves the simulated AWS account (G0 M20 D254).
func runAWS(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("aws", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9097", "listen address (loopback)")
	secretFile := fs.String("secret-file", "", "file holding the base access key's secret (required); the key id is "+aws.BaseKeyID)
	externalID := fs.String("external-id", "", "external id every AssumeRole must carry")
	actions := fs.String("role-actions", "*", "comma-separated actions the role's own policies allow (service:Action, or *)")
	throttle := fs.Int("throttle", 0, "answer the first N requests with Throttling")
	deny := fs.Bool("deny-assume-role", false, "refuse every AssumeRole")
	long := fs.Bool("long-sessions", false, "issue hour-long sessions whatever is asked")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *secretFile == "" {
		return errors.New("--secret-file is required")
	}
	b, err := os.ReadFile(*secretFile)
	if err != nil {
		return err
	}
	secret := strings.TrimSpace(string(b))
	if len(secret) < 16 {
		return errors.New("--secret-file must hold a secret of at least 16 characters")
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := aws.New(secret, *externalID, slackList(*actions), aws.Faults{Throttle: *throttle, DenyAssumeRole: *deny, LongSessions: *long}, log)
	return serve(ctx, *addr, sim.Handler(), log, "sim.aws_listening")
}
