# ADR-0059 — Kubernetes containment

**Status:** Proposed (2026-11-05; the [G0 M32](../g0/M32.md) brief records the coordinator decisions D964–D973). A stub: it is completed when M32's code is tested.

**Context.** Agents run as pods in customers' clusters, where the Docker sandbox's closure (G0 M9) does not reach: there is no `pclaw` host to create the network, no per-session probe key made outside the containers, and the pod's network is the cluster's. Coverage can only read ENFORCED for such an agent when something shows its only route is the gateway.

**Decision.**
1. **Protected namespaces and a fail-closed admission webhook** (HR-730..735; founder decision FQ32-1). A labelled namespace's pods are agent pods; the webhook admits one only with an issuer entry, one app container, pinned images and the edge as its native sidecar holding the only projected token.
2. **The edge as a native sidecar** (HR-736..738; FQ32-2). Loopback only, keys in memory, enrolled by kubernetes attestation; it signs the pod's probe reports with the pod's workload key.
3. **Egress only to the gateway** (HR-740; FQ32-3). The chart's NetworkPolicy allows only the gateway pods and the api, with no DNS (D965a); the gateway enrols from its own projected token (HR-739).
4. **Kube closures** (HR-741..743). A daily probe run, with a control twin in the release namespace, is checked by the server against the signer's attested namespace, the admission digest lists and a fresh nonce; the server adds its own admission and NetworkPolicy checks and evaluates it under the `ContainmentKubernetes` profile.
5. **Pod runs under the issuer entry's run grant** (HR-744, D973).
6. **Self-hosted clusters only** in M32 (FQ32-4).

**Consequences.**
- A cluster whose CNI ignores NetworkPolicy never shows ENFORCED for its agent pods (R-76).
- The edge shares the pod network with the agent; a bypass is refused by PAP/1 and the policy, not by the pod (R-77).
- The webhook secret sits in the cluster's configuration, visible to its admins (R-75).
- T1610 and T1613 leave Outside on the threat map.

**Alternatives.** A per-pod network namespace of PantherClaw's own (needs a CNI plugin); a DaemonSet edge per node (shares a key across pods); failing open when the webhook is down (FQ32-1 chose closed).
