// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

import (
	"fmt"
	"slices"
)

// The range step of Kubernetes enforcement (G0 M32; RT-215..RT-219,
// T-335..T-339):
//
//   - kube.probe {attack}: the stack serves a fake cluster "home" for its
//     org (TokenReview, pods, NetworkPolicies), the admission listener, a
//     kubernetes issuer entry with a run grant for a probe pod in namespace
//     agents, one without for a control pod in the release namespace, and
//     the seeded gateway bound to a gateway pod's service account. Each
//     attack is what someone in or beside an agent pod tries. REFUSED with
//     the server's reason when it was refused (admission: the deny's code;
//     a missing webhook path NOT_FOUND; a closure that does not pass
//     NOT_ENFORCED), ALLOW when it got through. Harness-only: it rewires the
//     server's configuration and plants entries, grants and pods.
const stepKubeProbe = "kube.probe"

// KubeAttacks are the kube.probe attacks.
var KubeAttacks = []string{
	// T-335: admission.
	"pod_without_edge", "host_network", "exposed_token", "ephemeral_container", "guessed_webhook_path",
	// T-336: the pod's run.
	"pod_run_other_name", "pod_run_without_grant", "pod_run_not_kubernetes",
	// T-337: gateway enrolment.
	"gateway_token_reused", "gateway_other_service_account",
	// T-338: forged or replayed closures.
	"report_other_key", "report_nonce_replayed", "nonce_other_namespace", "probe_image_off_list",
	"edge_image_off_list", "report_other_pod", "nonce_expired", "nonce_flood", "closure_not_kubernetes",
	"control_from_agent_pod", "sandbox_from_release_namespace", "result_without_target",
	// T-339: closures that overstate containment.
	"network_policy_open", "admission_not_seen", "probe_reached", "probe_target_forged",
}

func init() {
	StepKinds = append(StepKinds, stepKubeProbe)
	harnessOnlyKinds = append(harnessOnlyKinds, stepKubeProbe)
	kindsNeedingEx[stepKubeProbe] = true
	uiStepKinds[stepKubeProbe] = func(strict func(any) error) error {
		var w struct {
			Attack string `json:"attack"`
		}
		if err := strict(&w); err != nil {
			return err
		}
		if !slices.Contains(KubeAttacks, w.Attack) {
			return fmt.Errorf("attack must be one of %v", KubeAttacks)
		}
		return nil
	}
}
