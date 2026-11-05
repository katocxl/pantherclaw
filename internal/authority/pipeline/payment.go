// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"

	apdomain "github.com/katocxl/pantherclaw/internal/approvals/domain"
	adomain "github.com/katocxl/pantherclaw/internal/authority/domain"
	bdomain "github.com/katocxl/pantherclaw/internal/budgets/domain"
	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	gdomain "github.com/katocxl/pantherclaw/internal/grants/domain"
	"github.com/katocxl/pantherclaw/internal/payments/ap2"
	"github.com/katocxl/pantherclaw/internal/platform/ids"
	"github.com/katocxl/pantherclaw/internal/platform/money"
	pdomain "github.com/katocxl/pantherclaw/internal/policy/domain"
	td "github.com/katocxl/pantherclaw/internal/tenancy/domain"
)

// The payment step (G0 M39 D1124, D1124a, D1124b, D1124d; FQ39-2; HR-834,
// HR-835, HR-837). It applies to an action whose pinned definition has a
// payment block. The server verifies the mandate itself, outside any
// snapshot (VerifyPayments, before the second pass), against the org's
// ACTIVE sandbox trust anchors and the connection's merchant audience; a
// customer gateway never vouches for a mandate. The step then refuses a
// missing mandate (MANDATE_REQUIRED), one that did not verify or expired
// (MANDATE_INVALID), one outside the sandbox (PAYMENTS_LIVE_REFUSED), one
// whose amount, currency or merchant are not exactly the params
// (MANDATE_MISMATCH) and one already used in the org (MANDATE_REPLAYED).
// Otherwise every payment holds for a person (PAYMENT_APPROVAL), unless an
// ACTIVE merchant cap allows it: the amount at most its per-payment limit
// and the day's cap-allowed total plus the amount at most its per-day
// limit, debited to an account the cap owns. Over a cap holds, never
// denies. The approval binds the mandate digest.

// Reason codes and level of the payment step.
const (
	ReasonMandateRequired     = "MANDATE_REQUIRED"
	ReasonMandateInvalid      = "MANDATE_INVALID"
	ReasonMandateMismatch     = "MANDATE_MISMATCH"
	ReasonMandateReplayed     = "MANDATE_REPLAYED"
	ReasonPaymentsLiveRefused = "PAYMENTS_LIVE_REFUSED"
	ReasonPaymentApproval     = "PAYMENT_APPROVAL"
	ReasonPaymentCapAllowed   = "PAYMENT_CAP_ALLOWED"
	// PaymentLevel is the source of the payment hold's requirement.
	PaymentLevel = "payment"
	// PaymentFact is the name the verified mandate's facts are bound and
	// shown under.
	PaymentFact = "payments.mandate"
)

// PaymentWant is what the action asks to pay, from its params.
type PaymentWant struct {
	AmountMinor int64
	Currency    string
	Merchant    string
}

// PaymentVerifier verifies a payment mandate on the server (D1124d): with
// the org's ACTIVE trust anchors and the connection's merchant audience. It
// is called with no snapshot open. ap2.ErrInvalid, ap2.ErrLiveRefused (the
// verifier also quarantines the connection) or a mismatch with want are
// refusals; any other error is evidence that could not be read. It audits
// payments.mandate_verified or payments.mandate_refused.
type PaymentVerifier interface {
	VerifyMandate(ctx context.Context, org ids.OrgID, connection ids.UUID, raw string, want PaymentWant) (ap2.Verified, error)
}

// PaymentCap is an ACTIVE merchant cap as the payment step applies it.
type PaymentCap struct {
	ID                 ids.UUID
	MaxPerPaymentMinor int64
	MaxPerDayMinor     int64
}

// PaymentReads is the port the payment step reads caps and earlier uses
// through. A Reader that does not implement it cannot decide a payment
// (CANNOT_AUTHORIZE: fail closed).
type PaymentReads interface {
	// PaymentCap returns the ACTIVE cap of merchant in currency, if any.
	PaymentCap(ctx context.Context, org ids.OrgID, merchant, currency string) (PaymentCap, bool, error)
	// MandateUse returns the transaction that already used digest, if any.
	MandateUse(ctx context.Context, org ids.OrgID, digest string) (ids.UUID, bool, error)
}

// Payment is a verified payment an evaluation decided: the finalization
// records its single use with the permit (D1124b), and settlement records
// payments.effect from it (HR-840). Digests and verified facts only.
type Payment struct {
	MandateDigest string
	Merchant      string
	Currency      string
	AmountMinor   int64
	// TransactionID is the mandate's AP2 transaction id.
	TransactionID string
	// Cap is the ACTIVE cap that allowed it without a person, or zero.
	Cap ids.UUID
}

// paymentRound carries the verifications made with no snapshot open.
type paymentRoundKey struct{}

type paymentResult struct {
	v   ap2.Verified
	err error
}

type paymentRound struct {
	org     ids.OrgID
	results map[string]paymentResult
}

// pendingPayment is a verification the first pass needs.
type pendingPayment struct {
	conn ids.UUID
	raw  string
	want PaymentWant
}

func paymentKey(conn ids.UUID, raw string, want PaymentWant) string {
	h := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d\x00%s\x00%s\x00%s", conn, want.AmountMinor, want.Currency, want.Merchant, raw))
	return hex.EncodeToString(h[:])
}

// VerifyPayments verifies, with no snapshot open, the mandates the first
// pass found; again says the caller decides once more with ctx. One round
// per decision.
func (p *Pipeline) VerifyPayments(ctx context.Context, org ids.OrgID, ev *Evaluation) (context.Context, bool) {
	if p.Payments == nil || ev == nil || len(ev.payments) == 0 {
		return ctx, false
	}
	if _, done := ctx.Value(paymentRoundKey{}).(paymentRound); done {
		return ctx, false
	}
	round := paymentRound{org: org, results: map[string]paymentResult{}}
	for _, pp := range ev.payments {
		v, err := p.Payments.VerifyMandate(ctx, org, pp.conn, pp.raw, pp.want)
		round.results[paymentKey(pp.conn, pp.raw, pp.want)] = paymentResult{v: v, err: err}
	}
	return context.WithValue(ctx, paymentRoundKey{}, round), true
}

// minorOf is a money value in its currency's minor units.
func minorOf(m money.Money) (int64, bool) {
	s, err := money.ToMinor(m)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	return n, err == nil
}

// payment runs the payment step (D1124).
func (p *Pipeline) payment(ctx context.Context, s *state) {
	if s.def == nil || s.def.Payment == nil {
		return
	}
	pb := s.def.Payment
	raw := s.vals[pb.MandateParam].Str
	if raw == "" {
		s.cl.add(StepBoundaries, adomain.Deny, ReasonMandateRequired, "a payment needs the person's payment mandate", PaymentLevel)
		return
	}
	amount, ok := minorOf(s.vals[pb.AmountParam].Money)
	if !ok {
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonMandateMismatch, "the amount is not in minor units of its currency", PaymentLevel)
		return
	}
	want := PaymentWant{AmountMinor: amount, Currency: s.vals[pb.CurrencyParam].Str, Merchant: s.vals[pb.MerchantParam].Str}
	round, ok := ctx.Value(paymentRoundKey{}).(paymentRound)
	var res paymentResult
	if ok && round.org == s.req.Org {
		res, ok = round.results[paymentKey(s.connID(), raw, want)]
	}
	if !ok {
		// The first pass: the server verifies the mandate with no snapshot
		// open and decides again (VerifyPayments). Without a verifier
		// (replay, simulation) nothing can allow it.
		s.ev.payments = append(s.ev.payments, pendingPayment{conn: s.connID(), raw: raw, want: want})
		s.cl.add(StepBoundaries, adomain.CannotAuthorize, ReasonEvidenceUnavailable, "the payment mandate is not verified yet", PaymentLevel)
		return
	}
	v := res.v
	switch {
	case errors.Is(res.err, ap2.ErrLiveRefused):
		s.cl.add(StepBoundaries, adomain.Deny, ReasonPaymentsLiveRefused, "agent payments run in sandbox only", PaymentLevel)
		return
	case errors.Is(res.err, ap2.ErrInvalid):
		s.cl.add(StepBoundaries, adomain.Deny, ReasonMandateInvalid, "the payment mandate did not verify", PaymentLevel)
		return
	case res.err != nil:
		s.missing(StepBoundaries, res.err, "the payment mandate's verification")
		return
	}
	// Exact match (HR-834): the verifier compared too; the step decides.
	if v.AmountMinor != want.AmountMinor || v.Currency != want.Currency || v.Merchant != want.Merchant {
		s.cl.add(StepBoundaries, adomain.Deny, ReasonMandateMismatch,
			fmt.Sprintf("the mandate pays %d %s to %s, not %d %s to %s", v.AmountMinor, v.Currency, v.Merchant,
				want.AmountMinor, want.Currency, want.Merchant), PaymentLevel)
		return
	}
	s.ev.Payment = &Payment{
		MandateDigest: v.MandateDigest, Merchant: v.Merchant, Currency: v.Currency, AmountMinor: v.AmountMinor,
		TransactionID: v.TransactionID,
	}
	if s.facts == nil {
		s.facts = map[string]fdomain.Value{}
	}
	s.facts[PaymentFact] = paymentFactValue(v)
	port, ok := p.Reader.(PaymentReads)
	if !ok {
		s.missing(StepBoundaries, errors.New("no payment reads"), "the payment's earlier uses and caps")
		return
	}
	used, found, err := port.MandateUse(ctx, s.req.Org, v.MandateDigest)
	if err != nil {
		s.missing(StepBoundaries, err, "the payment mandate's earlier uses")
		return
	}
	if found {
		s.cl.add(StepBoundaries, adomain.Deny, ReasonMandateReplayed,
			"the payment mandate "+v.MandateDigest+" was already used (transaction "+used.String()+")", PaymentLevel)
		return
	}
	detail := fmt.Sprintf("pay %d %s (minor units) to %s under the verified mandate %s", v.AmountMinor, v.Currency, v.Merchant, v.MandateDigest)
	if p.capAllows(ctx, s, port, v) {
		s.cl.note(StepBoundaries, StatusPassed, ReasonPaymentCapAllowed, detail+" within the merchant cap")
		return
	}
	s.cl.add(StepRequirements, adomain.RequireApproval, ReasonPaymentApproval,
		"approval by "+string(td.RoleApprover)+" is required: "+detail, PaymentLevel)
	a := pdomain.ApprovalRequirement{Role: string(td.RoleApprover), Count: 1}
	s.ev.Approvals = append(s.ev.Approvals, a)
	s.ev.Requirements = append(s.ev.Requirements, input(&a, nil, apdomain.Source{Level: PaymentLevel, Reason: ReasonPaymentApproval}))
}

// capAllows reports whether an ACTIVE cap allows the payment without a
// person; then the cap's day debit joins the plan (budgets).
func (p *Pipeline) capAllows(ctx context.Context, s *state, port PaymentReads, v ap2.Verified) bool {
	c, found, err := port.PaymentCap(ctx, s.req.Org, v.Merchant, v.Currency)
	if err != nil || !found || v.AmountMinor > c.MaxPerPaymentMinor {
		return false // unread, none or over: a person decides
	}
	cur, err := money.ParseCurrency(v.Currency)
	if err != nil {
		return false
	}
	limitM, err1 := money.FromMinor(c.MaxPerDayMinor, cur)
	amountM, err2 := money.FromMinor(v.AmountMinor, cur)
	if err1 != nil || err2 != nil {
		return false
	}
	owner := bdomain.Owner{Kind: bdomain.OwnerPaymentCap, ID: c.ID, Rank: bdomain.PaymentCapRank}
	limit := limitM.Amount
	d := bdomain.Debit{
		Ref: bdomain.Ref{Owner: owner, Rule: bdomain.PaymentCapRule, Key: bdomain.KeyHash(owner, bdomain.PaymentCapRule, v.Merchant),
			Start: bdomain.PeriodDay.Start(s.cont.Now)},
		Grouping: bdomain.GroupMerchant, Period: bdomain.PeriodDay, Unit: bdomain.UnitCurrency, Currency: cur,
		Limit: &limit, Amount: amountM.Amount,
	}
	usage, err := p.Reader.Usage(ctx, s.req.Org, gdomain.Plan{Budgets: []bdomain.Debit{d}})
	if err != nil {
		return false
	}
	acc := usage.Accounts[d.Ref]
	acc.ID, acc.Rank, acc.Currency, acc.Limit, acc.Unit = ids.NewV7(), owner.Rank, cur, &limit, bdomain.UnitCurrency
	book := bdomain.NewBook()
	book.Accounts[acc.ID] = &acc
	if _, err := book.Check([]bdomain.Line{{Kind: bdomain.KindBudget, ID: acc.ID, Rank: acc.Rank, Amount: d.Amount}}); err != nil {
		return false // over the day's cap: held for a person, never denied
	}
	s.payDebit = &d
	s.ev.Payment.Cap = c.ID
	return true
}

// paymentFactValue is the verified mandate as an object fact, for the
// approval and the binding: facts and a digest, never the mandate.
func paymentFactValue(v ap2.Verified) fdomain.Value {
	return fdomain.Value{Type: fdomain.TypeObject, Object: map[string]any{
		"mandate_valid": true, "amount_minor": v.AmountMinor, "currency": v.Currency, "merchant": v.Merchant,
		"payee": v.Payee, "mandate_digest": v.MandateDigest,
	}}
}

// paymentBoundFacts bind the verified mandate digest (HR-837).
func (s *state) paymentBoundFacts() []apdomain.BoundFact {
	if s.ev == nil || s.ev.Payment == nil {
		return nil
	}
	return []apdomain.BoundFact{{
		Fact: PaymentFact, Subject: s.a.Target.Type + ":" + s.a.Target.ID, Member: "mandate_digest", Value: s.ev.Payment.MandateDigest,
	}}
}
