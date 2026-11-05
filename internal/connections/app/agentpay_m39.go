// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package app

import (
	"github.com/katocxl/pantherclaw/internal/payments/sandbox"
	pcerr "github.com/katocxl/pantherclaw/internal/platform/errors"
)

// agentPayPackage is the agent payments package (G0 M39 D1124).
const agentPayPackage = "pc.agentpay"

// ErrPaymentsLiveRefused is a pc.agentpay merchant endpoint that is not an
// https URL on the sandbox host allow-list (G0 M39 D1124c, HR-831): agent
// payments run in sandbox only, and there is no live switch.
var ErrPaymentsLiveRefused = pcerr.New(pcerr.FailedPrecondition, "PAYMENTS_LIVE_REFUSED",
	"agent payments run in sandbox only: the merchant endpoint must be an https URL on a sandbox host")

// checkAgentPayEndpoint refuses a pc.agentpay connection whose merchant
// endpoint is not a sandbox endpoint, when it is created or its base URL
// changes, so it fails before any payment; the server checks it again at
// every decision and the gateway at every dispatch.
func checkAgentPayEndpoint(pkg, baseURL string) error {
	if pkg != agentPayPackage {
		return nil
	}
	if ok, isSandbox := sandbox.URL(baseURL); !ok || !isSandbox {
		return ErrPaymentsLiveRefused
	}
	return nil
}
