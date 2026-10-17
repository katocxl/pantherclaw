// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"maps"

	fdomain "github.com/katocxl/pantherclaw/internal/facts/domain"
	pcstripe "github.com/katocxl/pantherclaw/packages/pc-stripe"
)

// The M14 templates (G0 M14 D40, F172): support and internal analysis,
// and the treasury, aggregate-reporting and research-disclosure templates
// the reference packs apply. They go through the same checks as the M11.1
// templates (template_m11_test.go): a complete disclosure, a policy that
// compiles against its packages, scenario tests in the D7 format, and the
// publish gate's mutation run with no survivors (HR-044).

// m14Templates are the M14 templates that carry scenario tests.
var m14Templates = []string{"customer-support"}

// m14Manifests are the business-connector packages the templates require.
var m14Manifests = [][]byte{pcstripe.Package}

// m14Facts are the facts the business-connector packages' gateway reads
// provide (the stripe.* facts of internal/gateway/stripefacts).
var m14Facts = map[string]fdomain.Type{
	"stripe.payment.refundable":             fdomain.TypeObject,
	"stripe.account.payout_details_changed": fdomain.TypeObject,
}

func init() { maps.Copy(m11Facts, m14Facts) }
