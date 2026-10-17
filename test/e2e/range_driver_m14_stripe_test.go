// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

//go:build integration

package e2e

import (
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"

	"github.com/katocxl/pantherclaw/internal/redteam/app"
	"github.com/katocxl/pantherclaw/internal/redteam/domain"
	"github.com/katocxl/pantherclaw/internal/sim/stripe"
)

// The range driver's Stripe part (G0 M14 D14, D46): RT-039..041 run on a
// stack with the Stripe simulator and the seeded connection "stripe".

// stripeCapabilities are the Stripe capabilities this driver offers.
func stripeCapabilities() map[app.Capability]bool {
	return map[app.Capability]bool{"stripe.refund": true, "stripe.transfer": true, "stripe.key_swap": true}
}

// needsStripe reports whether a scenario runs on the Stripe simulator.
func needsStripe(sc domain.Scenario) bool {
	return requires(sc, "stripe.refund") || requires(sc, "stripe.transfer") || requires(sc, "stripe.key_swap")
}

// setupStripe names the simulator's fixtures for the scenarios.
func (d *rangeDriver) setupStripe() {
	d.fix["stripe_payment"] = stripe.FixturePayment
	d.fix["stripe_payment_small"] = stripe.FixturePayment2
	d.fix["stripe_payment_eur"] = stripe.FixturePaymentEUR
	d.fix["stripe_payee"] = stripe.FixturePayee
	d.fix["stripe_other_payee"] = stripe.FixturePayee2
}

// mutateStripe changes what the Stripe connection holds: sealed_key live
// swaps a live key into it, as a careless or hostile admin would (RT-039).
func (d *rangeDriver) mutateStripe(change string, args jsontext.Value) (domain.Observation, error) {
	var a struct {
		SealedKey string `json:"sealed_key"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return domain.Observation{}, err
	}
	if change != "fault" || a.SealedKey != "live" {
		return domain.Observation{}, fmt.Errorf("sim.mutate stripe %s %s", change, args)
	}
	d.s.waitConfig(d.t, d.s.sealStripeKey(d.t, stripeLiveKey))
	return domain.Observation{}, nil
}

// contentType is the body type a connection's HTTP face takes: Stripe's
// is form-encoded.
func contentType(conn string) string {
	if conn == "stripe" {
		return "application/x-www-form-urlencoded"
	}
	return "application/json"
}
