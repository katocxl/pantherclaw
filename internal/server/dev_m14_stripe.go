// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package server

import (
	"context"
	"encoding/json/jsontext"
	"fmt"
	"io"
	"maps"
	"net/url"
	"slices"
	"time"

	"github.com/katocxl/pantherclaw/internal/actionir"
	capp "github.com/katocxl/pantherclaw/internal/connections/app"
	"github.com/katocxl/pantherclaw/internal/evidence/audit"
	factspg "github.com/katocxl/pantherclaw/internal/facts/adapters/pgstore"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/platform/celenv"
	"github.com/katocxl/pantherclaw/internal/platform/db"
	"github.com/katocxl/pantherclaw/internal/platform/httpx"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	"github.com/katocxl/pantherclaw/internal/policy/rollout"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

// devStripeConnectionName is the development Stripe connection: agents call
// the gateway at /stripe/v1/refunds and /mcp/stripe (G0 M14 D14).
const devStripeConnectionName = "stripe"

// The development Stripe grant (D14): refunds up to devStripeMax, one
// refund per task, and the reads; refunds over devStripeHoldOver wait for
// an approver.
const (
	devStripeMax       = "100.00"
	devStripeHoldOver  = "50.00"
	devStripeCurrency  = "USD"
	devStripeHoldRsn   = "STRIPE_REFUND_NEEDS_APPROVAL"
	devStripePolicyID  = "dev-stripe-holds"
	devStripeBudgetID  = "stripe-refunds"
	devStripeRefundOp  = "stripe.refund.create"
	devStripeTargetTyp = "stripe.payment"
)

// stripeOperations are the pc.stripe operations the seeded grant allows
// with --stripe-url: refunds, charges and transfers up to devStripeMax
// each, transfers only to the seeded payee.
var stripeOperations = []string{
	devStripeRefundOp, "stripe.refund.read", "stripe.payment_intent.read", "stripe.balance.read", "stripe.payment_intent.create",
	"stripe.payment_intent.cancel", "stripe.transfer.create", "stripe.transfer.read", "stripe.payee.changed_recently",
}

// devStripePayee is the connected account the seeded grant may transfer to
// by default (the simulator's first payee).
const devStripePayee = "acct_SimPayee0001"

// devStripePackage is pc.stripe for dev seed's package import.
func devStripePackage() devPackage {
	return devPackage{pcstripe.Name, pcstripe.Version, pcstripe.Package}
}

// seedStripe creates the development Stripe connection to targetURL (the
// Stripe simulator, pantherclaw-sim stripe), held by the gateway, registers
// the gateway as the provider of the stripe.* facts and publishes the
// refund hold. A person seals the restricted test key afterwards (pclaw
// seal): the gateway's broker key exists only once it has started, and
// the gateway refuses any key that is not a test key before sending
// (HR-303). DEVELOPMENT ONLY.
func seedStripe(ctx context.Context, cfg *Config, pool *db.Pool, org ids.OrgID, gateway ids.UUID, targetURL string, stdout io.Writer) error {
	class := capp.ClassPublic
	if u, err := url.Parse(targetURL); err == nil {
		if a, isIP := httpx.HostAddr(u.Hostname()); isIP && (a.IsPrivate() || a.IsLoopback()) {
			class = capp.ClassInternal
		}
	}
	c, err := capp.New(pool, nil, cfg.Auth.PublicURL, cfg.GatewayAPI.URL).Seed(ctx, org, "dev-seed", capp.CreateInput{
		Name: devStripeConnectionName, Kind: capp.KindHTTP, Package: pcstripe.Name, BaseURL: targetURL, Gateway: gateway,
		DestinationClass: class, AccessMode: capp.AccessHeld, DefaultMode: "enforce",
		CredentialHeader: "Authorization", CredentialScheme: "Bearer",
	})
	if err != nil {
		return fmt.Errorf("dev: stripe connection: %w", err)
	}
	if err := seedStripeFacts(ctx, pool, org, gateway, c.ID); err != nil {
		return err
	}
	if _, err := seedStripeHoldPolicy(ctx, pool, org, cfg.CEL); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(stdout, "seeded stripe connection %s (%s) to %s, its facts read by the gateway, refunds over %s %s held (%s); "+
		"seal a restricted test key with pclaw seal --connection %s --from-file KEY\n",
		c.ID, c.Name, targetURL, devStripeHoldOver, devStripeCurrency, devStripeHoldRsn, c.ID)
	return nil
}

// seedStripeFacts registers the gateway serving the Stripe connection as the
// provider of every fact pc.stripe names (D51). DEVELOPMENT ONLY.
func seedStripeFacts(ctx context.Context, pool *db.Pool, org ids.OrgID, gateway, conn ids.UUID) error {
	named, err := packageFacts(pool)(ctx, org, gateway, conn)
	if err != nil {
		return fmt.Errorf("dev: stripe facts: %w", err)
	}
	var decls []fdomain.Declaration
	for _, name := range slices.Sorted(maps.Keys(named)) {
		for _, subject := range named[name] {
			decls = append(decls, fdomain.Declaration{Name: name, Type: fdomain.TypeObject, SubjectType: subject, MaxLag: time.Minute})
		}
	}
	p := fdomain.Provider{
		ID: ids.NewV7(), Org: org, Name: "stripe.gateway", GatewayID: gateway, ConnectionID: conn, State: fdomain.ProviderActive, Facts: decls,
	}
	ev := audit.Event{
		Name: "facts.provider_registered", Actor: devSeedActor, Outcome: audit.Success,
		Object:  &audit.Object{Type: "fact_provider", ID: p.ID.String()},
		Details: map[string]string{"gateway": gateway.String(), "connection": conn.String(), "facts": fmt.Sprint(len(decls))},
	}
	if err := (&factspg.Store{Pool: pool}).CreateProvider(ctx, org, p, "dev-seed", ev); err != nil {
		return fmt.Errorf("dev: stripe facts: %w", err)
	}
	return nil
}

// devStripeHoldBundle holds Stripe refunds over devStripeHoldOver for one
// approver. Its scenario tests hold a refund one cent over and allow one
// at the limit.
func devStripeHoldBundle() *pdomain.Bundle {
	refund := func(id, value string, expect pdomain.TestExpect) pdomain.TestCase {
		return pdomain.TestCase{
			ID: id, Summary: "a Stripe refund of " + value + " " + devStripeCurrency,
			Action: pdomain.TestAction{
				Operation: devStripeRefundOp, Target: &actionir.Target{Type: devStripeTargetTyp, ID: "pi_DevPayment0001"},
				Params: jsontext.Value(fmt.Sprintf(`{"amount":{"value":%q,"currency":%q},"reason":"duplicate"}`, value, devStripeCurrency)),
			},
			Given: &pdomain.TestGiven{Facts: map[string]pdomain.TestFact{
				"stripe.payment.refundable": {
					Value: jsontext.Value(`{"object":{"livemode":false,"payment":"ch_DevCharge0001",` +
						`"remaining":{"currency":"USD","value":"150.00"}}}`),
					AgeSeconds: 10,
				},
			}},
			Expect: expect,
		}
	}
	return &pdomain.Bundle{ID: devStripePolicyID, Version: 1, Rules: []pdomain.Rule{{
		ID: "approve-large-stripe-refunds", Kind: pdomain.RequireApproval,
		Summary:    "Stripe refunds over " + devStripeHoldOver + " " + devStripeCurrency + " need an approver",
		Operations: []string{devStripeRefundOp},
		When:       fmt.Sprintf("action.params.amount > money(%q, %q)", devStripeHoldOver, devStripeCurrency),
		Reason:     devStripeHoldRsn, Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}}, Tests: []pdomain.TestCase{
		refund("over-the-limit-is-held", "50.01", pdomain.TestExpect{
			Decision: "REQUIRE_APPROVAL", Reason: devStripeHoldRsn, Rule: "approve-large-stripe-refunds",
		}),
		refund("at-the-limit-is-allowed", devStripeHoldOver, pdomain.TestExpect{Decision: "ALLOW", Reason: "GRANT_COVERS"}),
	}}
}

// seedStripeHoldPolicy publishes devStripeHoldBundle through the publish
// gate like any version.
func seedStripeHoldPolicy(ctx context.Context, pool *db.Pool, org ids.OrgID, limits celenv.Limits) (ids.UUID, error) {
	v := newPolicyVersions(pool, nil, "", limits)
	rollout.Connect(v, &rollout.Service{Pool: pool})
	id, err := v.Seed(ctx, org, devStripeHoldBundle(), devSeedActor)
	if err != nil {
		return ids.UUID{}, fmt.Errorf("dev seed: stripe hold policy: %w", err)
	}
	return id, nil
}

// stripeGrant is what the seeded grant adds with --stripe-url: the
// operations, the per-refund maximum and the one-refund budget.
func stripeGrant(payee string) (ops []string, params, budget map[string]any, destinations []string) {
	maxAmount := map[string]any{"amount": map[string]any{"max": map[string]string{devStripeCurrency: devStripeMax}}}
	return stripeOperations,
		map[string]any{devStripeRefundOp: maxAmount, "stripe.payment_intent.create": maxAmount, "stripe.transfer.create": maxAmount},
		map[string]any{
			"id": devStripeBudgetID, "grouping": "task", "operations": []string{devStripeRefundOp}, "max_count": "1", "period": "none",
		}, []string{payee}
}

// stripeRequirement holds a transfer whose payee's bank details changed
// within 7 days, or could not be read (HR-306), for an approver: the
// consequence stripe.payee.changed_recently is decided like a write.
func stripeRequirement() gdomain.Requirement {
	return gdomain.Requirement{
		Operations: gdomain.Ops{"stripe.payee.changed_recently"}, Reason: "PAYEE_CHANGED_RECENTLY",
		Approval: &pdomain.ApprovalRequirement{Role: "approver", Count: 1},
	}
}
