# ADR-0059 — Kubernetes containment

**Status:** Proposed (2026-11-05, with the [G0 M32](../g0/M32.md) brief, which records the founder decisions FQ32-1..4 and the coordinator decisions D964–D973). The body was completed on 2026-11-06 with M32's tests (Phase B). Runbook: [kubernetes.md](../runbooks/kubernetes.md).

**Context.** Agents run as pods in customers' clusters, where the Docker sandbox's closure (G0 M9) does not reach: there is no `pclaw` host to create the network, no per-session probe key made outside the containers, and the pod's network is the cluster's. Coverage can only read ENFORCED for such an agent when something shows its only route is the gateway. Two questions need separate answers (D1205): is this pod's agent the one it claims to be, acting for whom (agent identity protection), and may the pod reach anything but the gateway (the runtime firewall).

**Decision.**

*Agent identity protection (Badge).*
1. **The pod's workload key is the edge's** (HR-737). The edge generates an Ed25519 key in memory at start, enrols it with Kubernetes attestation from the pod's projected token (audience `pantherclaw:<org>`, TokenReview against the configured cluster), and renews by attesting again with a fresh token. The key is never written. Enrolment stays `enrolled_via = attestation`, at L2.
2. **The gateway enrols from its own projected token** (HR-739, D968). A gateway record bound to one cluster, namespace and service account (UID included, image digests optional) enrols replicas by TokenReview with audience `pantherclaw-gateway:<org>`, each token once (D968a). Setting or clearing the binding needs `gateways.manage` and is audited. A request carries a projected token or a `pcg_` token, never both.
3. **Pod runs under the issuer entry's run grant** (HR-744, D973, D973a). `KubernetesService.StartPodRun` starts the run of the attested pod name only, launched by the instance through the entry (`principal_source = trusted_issuer`, `launcher_issuer_id`), with the grant's principal. An entry without a run grant starts nothing (`K8S_NO_RUN_GRANT`); `StartRun`'s launcher check is not loosened.

*Runtime firewall.*
4. **Enforced namespaces and a fail-closed admission webhook** (HR-730..735; FQ32-1). A namespace labelled `pantherclaw.dev/protect=enforce` and `pantherclaw.dev/org` holds only agent pods. The webhook, on its own TLS listener that is off by default, behind a path that names the cluster, the org and a secret, admits a pod only with an issuer entry, one app container, pinned images when the entry pins them, exactly one `pantherclaw-edge` native sidecar with a listed digest, no host access, and the projected token mounted only into the edge. It denies every ephemeral container and anything it cannot decide (`K8S_UNAVAILABLE`), and `failurePolicy` is `Fail`. Denies are audited once a minute per key; allows only touch a metric and the seen row the closure reads (D967a).
5. **The edge as a native sidecar** (HR-736, HR-738; FQ32-2). Loopback only on `127.0.0.1:3128`, no fixed run, the session CA key in memory and only its certificate in the shared `/pc-edge`. Its loopback `/__pc/report` signs the probe's report with the pod's key and submits it, and signs nothing else.
6. **Egress only to the gateway and the api** (HR-740; FQ32-3, D965, D965a). The chart's NetworkPolicy per agent namespace allows no ingress and egress only to the release namespace's gateway pods and api pods (or `apiEgressCIDRs` for an external server), with no DNS: agent pods reach both by fixed Service addresses through `hostAliases`.
7. **Kube closures** (HR-741..743; D970, D970b, D970c). A daily probe CronJob in each agent namespace and a control twin in the release namespace post reports to their edges. The server accepts one only from an L2 Kubernetes instance, for its attested namespace, with a fresh single-use nonce, and reads the pod's edge and probe digests from the cluster, never from the report. It adds its own checks, `admission_enforced` and `netpol_egress_gateway_only`, and evaluates under the `ContainmentKubernetes` profile: a kind closes only when every probe was unreachable with its twin reachable, the edge's controls passed and both checks hold. A passing closure is recorded per connection whose hosts the edge mediated and expires after 24 hours; there are no new invalidation kinds.
8. **Self-hosted clusters only** in M32 (FQ32-4); hosted clusters later, relayed through the customer's gateway.

*Both.* The threat map gains `prevent.kubernetes_admission` (T1610) and `prevent.kubernetes_closure` (T1552.005, T1613); T1610 and T1613 leave Outside.

**Consequences.**
- A cluster whose CNI ignores NetworkPolicy never shows ENFORCED for its agent pods: the probes reach their targets and the closure fails (R-76).
- The edge shares the pod network with the agent; a request that skips it is refused by PAP/1 and the NetworkPolicy, not by the pod (R-77).
- The webhook secret sits in the cluster's configuration, visible to its admins (R-75). A GitOps re-render rotates it and rolls the API pods; pods may be denied for a minute or two meanwhile, failing closed (D969a, D969b).
- The admission certificate pair is staged at pod start, so a rotated TLS Secret takes effect when the API pods roll; the runbook gives the cert-manager and manual paths, and no in-pod refresher is needed.
- With the webhook down, no pod starts in an enforced namespace; running pods are unaffected.
- A kube closure is signed by the pod's attested workload key, not by a host (R-17 note).

**Alternatives.** A per-pod network namespace of PantherClaw's own (needs a CNI plugin); a DaemonSet edge per node (shares a key across pods); failing open when the webhook is down (FQ32-1 chose closed); trusting the report's own image digests (the server reads the pod instead, D970b); a stage-secrets refresher for the admission TLS (rolling the pods is enough and fails closed).
