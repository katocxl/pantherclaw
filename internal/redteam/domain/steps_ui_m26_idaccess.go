// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The M26 IdP-native access range step (G0 M26 D400-D403, D408;
// RT-150..RT-153):
//
//   - idp.probe {attack}: the org trusts a simulated Okta, binds an Okta
//     client to the range agent, allow-lists a standard MCP client and
//     turns MCP authorization on for the range gateway; a person of the
//     IdP holds a grant of the agent. Each attack then uses the token
//     endpoint's grants and the gateway's OAuth route. granted and
//     code_flow are the honest paths (ALLOW when a tool call ran). The
//     others are refused, and the reason is the OAuth error (upper case),
//     NO_GRANT, or the PAP/1 code of the gateway's refusal:
//     assertions: no_grant, replayed_assertion, expired_assertion,
//     wrong_audience; token confusion: mcp_token_on_pap_route,
//     workload_token_on_oauth_route, token_for_other_server,
//     proof_on_oauth_route; clients: unbound_client, key_of_no_instance,
//     removed_binding; the code flow: code_replay, wrong_verifier,
//     unregistered_redirect, refresh_reuse; bound tokens (G0 M30 D913,
//     RT-202): bound_token_as_bearer, bound_token_without_proof.
//     Harness-only: it seeds an issuer and a person and runs the token
//     endpoint against the simulated IdP.
const stepIdpProbe = "idp.probe"

// IdpAttacks are the idp.probe attacks.
var IdpAttacks = []string{
	"granted", "no_grant", "replayed_assertion", "expired_assertion", "wrong_audience",
	"mcp_token_on_pap_route", "workload_token_on_oauth_route", "token_for_other_server", "proof_on_oauth_route",
	"unbound_client", "key_of_no_instance", "removed_binding",
	"code_flow", "code_replay", "wrong_verifier", "unregistered_redirect", "refresh_reuse",
	"bound_token_as_bearer", "bound_token_without_proof",
}

func init() {
	StepKinds = append(StepKinds, stepIdpProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepIdpProbe)
	kindsNeedingEx[stepIdpProbe] = true
	uiStepKinds[stepIdpProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(IdpAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", IdpAttacks)
		}
		return nil
	}
}
