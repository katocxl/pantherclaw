// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package domain

// Containment is the profile a closure's evidence is evaluated under: the
// probes that close each containment kind, the configuration checks that
// must also be ok, and the controls it requires (G0 M32 D970).
type Containment string

// Containment profiles.
const (
	// ContainmentSandbox is pclaw's Docker sandbox (G0 M9): its probes,
	// pclaw's configuration checks and the external canary.
	ContainmentSandbox Containment = "sandbox"
	// ContainmentKubernetes is an agent pod in a protected namespace with
	// the edge as its native sidecar (G0 M32 D970). Its report is signed
	// with the pod's attested workload key; the server makes its checks.
	ContainmentKubernetes Containment = "kubernetes"
)

// RuntimeKubernetes is the runtime a kubernetes closure stores (the
// coverage_closures runtime CHECK, G0 M32 D970).
const RuntimeKubernetes = "kubernetes"

// ContainmentOf is the profile of a closure stored with runtime: a
// kubernetes closure, or a Docker sandbox's (runc or runsc).
func ContainmentOf(runtime string) Containment {
	if runtime == RuntimeKubernetes {
		return ContainmentKubernetes
	}
	return ContainmentSandbox
}

// Kubernetes probe names (the closure contract with the probe's
// kubernetes profile, G0 M32 D970). dns_external, direct_https, metadata,
// ipv6, edge_mediated and edge_unmapped_refused keep their sandbox names.
const (
	// ProbeKubeAPI is the cluster's API server (KUBERNETES_SERVICE_HOST).
	ProbeKubeAPI = "kube_api"
	// ProbeKubelet is the node's kubelet, on 10250 and 10255.
	ProbeKubelet = "kubelet"
	// ProbeNodeIP is the node's own address, on 22 and 443.
	ProbeNodeIP = "node_ip"
	// ProbeDNSCluster is the pod's cluster resolver, on UDP and TCP 53.
	ProbeDNSCluster = "dns_cluster"
	// ProbeServiceOther is another Service (the pantherclaw-canary one).
	ProbeServiceOther = "service_other"
	// ProbePodOther is another pod (the canary pod).
	ProbePodOther = "pod_other"
)

// Kubernetes configuration checks, made by the server (G0 M32 D970).
const (
	// CheckAdmissionEnforced: this server's admission webhook decided a pod
	// for the cluster and namespace within 24 hours.
	CheckAdmissionEnforced = "admission_enforced"
	// CheckNetpolEgressGatewayOnly: the namespace's NetworkPolicies have the
	// D965 shape, egress only to the gateway pods.
	CheckNetpolEgressGatewayOnly = "netpol_egress_gateway_only"
)

// profile is one containment profile's closure contract.
type profile struct {
	closingProbes map[RouteKind][]string
	closingChecks map[RouteKind][]string
	twinOptional  []string
	// positive are the required positive controls; edge_unmapped_refused
	// is every profile's required negative control.
	positive []string
	// canary: the external canary is required for Passed.
	canary bool
}

// kubeProbes are the kubernetes profile's blocked probes. An agent pod
// has one network boundary, its namespace's NetworkPolicy, so every
// containment kind closes only when all of them were blocked, each with
// its positive twin from the control run, and both server checks are ok.
var kubeProbes = []string{
	ProbeKubeAPI, ProbeKubelet, ProbeNodeIP, ProbeMetadata, ProbeDNSCluster, ProbeDNSExternal, ProbeDirectHTTPS,
	ProbeServiceOther, ProbePodOther, ProbeIPv6,
}

var kubeChecks = []string{CheckAdmissionEnforced, CheckNetpolEgressGatewayOnly}

var profiles = map[Containment]profile{
	ContainmentSandbox: {
		closingProbes: closingProbes, closingChecks: closingChecks, twinOptional: twinOptional,
		positive: []string{ProbeEdgeMediated, ProbeCanaryControl}, canary: true,
	},
	ContainmentKubernetes: {
		closingProbes: allKinds(kubeProbes), closingChecks: allKinds(kubeChecks), twinOptional: twinOptional,
		positive: []string{ProbeEdgeMediated},
	},
}

// containment is the record's profile; a record without one is a Docker
// sandbox's.
func (c *ClosureRecord) containment() Containment {
	if c.Containment == "" {
		return ContainmentSandbox
	}
	return c.Containment
}

func allKinds(names []string) map[RouteKind][]string {
	m := make(map[RouteKind][]string, len(ContainmentKinds))
	for _, k := range ContainmentKinds {
		m[k] = names
	}
	return m
}
