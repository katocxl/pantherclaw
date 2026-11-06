// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package auditkind

// Audit kinds of Kubernetes enforcement (G0 M32 D967, D968, D970), kept in
// one file: "kubernetes." and the gateway's Kubernetes binding. The ledger
// stores each as "audit." + the kind.
const (
	GatewayKubernetesBindingCleared = "gateway.kubernetes_binding_cleared"
	GatewayKubernetesBindingSet     = "gateway.kubernetes_binding_set"
	KubernetesAdmissionDenied       = "kubernetes.admission_denied"
	KubernetesClosureRecorded       = "kubernetes.closure_recorded"
)
