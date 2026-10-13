// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pipelinetest

import "strings"

// PayoutConsequence adds to the reference package a virtual payout that a
// refund may start, and the rule that predicts it from the charge's
// payments.charge.payouts object fact ({state, environments}), shaped as
// G0 M8's deployment consequences are (HR-206).
func PayoutConsequence(pkg string) string {
	const payout = `  - operation: payments.payout.trigger
    summary: A payout that a refund starts
    access: write
    target:
      type: payments.charge
      id_pattern: '^ch_[A-Za-z0-9]{1,64}$'
      account: none
    params: {}
    effects:
      - kind: funds.transfer
        description: Pays the merchant out
    reversibility: compensatable
    retry:
      safe: false
      on_unknown: reconcile
    approval:
      title: Release a payout for {target.id}
      fields: [target.id]
    assurance:
      basis: documented
      reviewed_by: [pantherclaw-maintainers]
      valid_until: 2027-10-08

`
	const rules = `
consequences:
  - id: refund-triggers-payout
    operation: payments.refund.create
    when: facts.payments_charge_payouts.state != 'none'
    requires_facts: [payments.charge.payouts]
    consequence:
      operation: payments.payout.trigger
      effect: funds.transfer
      environments: facts.payments_charge_payouts.environments
      description: A refund on a charge with a payout schedule starts a payout.
    valid_until: 2027-10-08
`
	const anchor = "# What the simulated API created"
	return strings.Replace(pkg, anchor, payout+anchor, 1) + rules
}

// PayoutBounds are RootBounds that also cover the payout.
const PayoutBounds = `{
  "operations": ["payments.refund.create", "payments.refund.get", "payments.payout.trigger"],
  "targets": {"payments.charge": {"prefixes": ["ch_"]}, "payments.refund": {"prefixes": ["re_"]}},
  "params": {"payments.refund.create": {"amount": {"max": {"USD": "100.00"}}}}
}`
