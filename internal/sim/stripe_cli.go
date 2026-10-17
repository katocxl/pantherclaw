// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package sim

import (
	"context"
	"flag"
	"io"
	"os"
	"strings"

	pclog "github.com/katocxl/pantherclaw/internal/platform/log"
	"github.com/katocxl/pantherclaw/internal/platform/version"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
)

// runStripe serves the simulated Stripe API in test mode with its fixtures
// (G0 M14).
func runStripe(ctx context.Context, args []string, stderr io.Writer) error {
	fs := flag.NewFlagSet("stripe", flag.ContinueOnError)
	fs.SetOutput(stderr)
	addr := fs.String("addr", "127.0.0.1:9093", "listen address (loopback)")
	latency := fs.Duration("latency", 0, "added latency per request")
	decline := fs.Float64("decline-rate", 0, "probability that a refund or payment intent is declined (402 card_declined)")
	lose := fs.Float64("lose-response-rate", 0, "probability that a create takes effect and then never answers")
	settle := fs.Duration("settle-after", 0, "how long a new refund stays pending and a payment intent processing")
	failAfter := fs.Bool("fail-after-pending", false, "new refunds end failed instead of succeeded once they settle")
	bankChanged := fs.Bool("bank-changed-recently", false, "every connected account reports a bank-account change one day ago")
	keyFile := fs.String("key-file", "", "file holding the only test key accepted (otherwise any sk_test_/rk_test_ key is)")
	liveKey := fs.String("livemode-key", "", "a key that is accepted and makes every object answer livemode: true (guard tests)")
	liveKeyFile := fs.String("livemode-key-file", "", "file holding the live-mode key (instead of --livemode-key)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	req := stripe.Require{LivemodeKey: *liveKey}
	if *liveKeyFile != "" {
		b, err := os.ReadFile(*liveKeyFile)
		if err != nil {
			return err
		}
		req.LivemodeKey = strings.TrimSpace(string(b))
	}
	if *keyFile != "" {
		b, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		req.Keys = []string{strings.TrimSpace(string(b))}
	}
	log := pclog.New(stderr, pclog.Options{Service: "pantherclaw-sim", Version: version.Get().Version})
	sim := stripe.New(stripe.Faults{
		Latency: *latency, DeclineRate: *decline, LoseRate: *lose, SettleAfter: *settle, FailAfterPending: *failAfter,
		BankChangedRecently: *bankChanged,
	}, log).WithRequire(req)
	return serve(ctx, *addr, sim.Handler(), log, "sim.stripe_listening")
}
