# Runbook: Kubernetes enforcement

**Milestone:** M32 ([G0 M32](../g0/M32.md), [ADR-0059](../adr/0059-kubernetes-containment.md)). **Rules:** HR-730..HR-744. **Edition:** that of platform attestation (PN-002.2, Community). Self-hosted clusters only (FQ32-4).

Agent pods in your own cluster get one route out: the edge, a native sidecar in each pod, to the in-cluster gateway. The work has two halves (D1205):

- **Agent identity protection (Badge):** the pod's workload key, enrolled from its projected service-account token by Kubernetes attestation; the gateway's enrolment from its own projected token; pod runs under the issuer entry's run grant.
- **Runtime firewall:** the admission webhook, the agent NetworkPolicy and the in-pod edge, which together leave the pod no route but the gateway; the daily kube closure shows that the route holds.

This runbook has three parts: [admission](#1-admission), [gateway enrolment in the cluster](#2-gateway-enrolment-in-the-cluster) and [closures](#3-closures).

## Before you start

- A cluster whose CNI enforces NetworkPolicy (Calico, Cilium, or another that does). On a CNI that ignores it, closures fail and coverage never reads ENFORCED (R-76).
- The cluster in the server configuration, `identity.kubernetes_clusters` (Helm `identity.kubernetesClusters`): `name`, `api_server`, `ca_file`, `token_file` (the reviewer token; in the chart, the server's own projected token with a `system:auth-delegator` binding), `allowed_prefixes`, `orgs` and `webhook_secret_file`.
- Each agent namespace labelled `pantherclaw.dev/protect=enforce` and `pantherclaw.dev/org=<org id>`. Every pod in such a namespace is an agent pod.
- The edge and probe image digests from the release notes, for `admission.edgeImageDigests` and `admission.probeImageDigests`.

## 1. Admission

### Turn it on

1. Create a `kubernetes.io/tls` Secret for the admission listener whose certificate names `<release>-pantherclaw-api.<namespace>.svc`, or let cert-manager issue it (below).
2. Set the Helm values:
   - `admission.enabled: true`, `admission.cluster: <name>` (an `identity.kubernetesClusters` entry);
   - `admission.tls.existingSecret`, and either `admission.tls.certManagerCertificate: <namespace>/<certificate>` or `admission.tls.caBundle` (base64 PEM);
   - `admission.edgeImageDigests` and `admission.probeImageDigests`;
   - `gateway.enabled`, `gateway.service.clusterIP`, `api.service.clusterIP` and `probe.canary.clusterIP` (fixed addresses: agent pods get no DNS, FQ32-3);
   - one `agentNamespaces[]` entry per namespace, with its `org` and `hosts` map.
3. `helm upgrade`. The chart refuses to render agent namespaces without the admission listener, the gateway or the fixed addresses.
4. For each agent, propose its issuer entry and have an Identity Publisher activate it:
   `pclaw issuer propose-kubernetes --agent <id> --cluster <name> --namespace <ns> --service-account <sa> --service-account-uid <uid> --image-digest <sha256:…> --run-grant <grant> --auto-admit --reason "…"`, then `pclaw issuer activate <entry> <revision>`.
5. Start a pod from `deploy/helm/pantherclaw/examples/agent-pod.yaml` with your values. It should be admitted; one without the edge should be denied `K8S_EDGE_MISSING`.

The listener is off by default (HR-731) and fails closed (HR-730): with the server down or the webhook unreachable, no pod starts in an enforced namespace. That is the intended trade (FQ32-1).

### Read a deny

`kubectl` shows the reason in the event: `admission webhook … denied the request: <code>`. Each deny is audited once a minute per cluster, namespace and code as `kubernetes.admission_denied`, with the pod name and service account (HR-735). Dry runs write nothing; allows only count in `pc_kubernetes_admission_total`.

| Code | Cause | Fix |
| --- | --- | --- |
| `K8S_NO_ISSUER` | No ACTIVE kubernetes issuer entry for the org, cluster, namespace and service account | Propose and activate one |
| `K8S_APP_CONTAINERS` | Not exactly one app container | One agent container per pod |
| `K8S_IMAGE_NOT_PINNED` | The entry pins images and the container's is not `repo@sha256:…` on its list | Pin the digest |
| `K8S_EDGE_MISSING` | No single `pantherclaw-edge` native sidecar with a listed digest | Use the example pod; update `admission.edgeImageDigests` after an edge upgrade |
| `K8S_POD_ESCAPE` | Host network, PID or IPC, a privileged container or a hostPath | Remove them |
| `K8S_TOKEN_EXPOSED` | Token automount on, or a projected token mounted outside the edge, with another audience or over 3600 s | `automountServiceAccountToken: false`; mount the token only into the edge |
| `K8S_EPHEMERAL` | An ephemeral container (`kubectl debug`) | Not allowed in an enforced namespace; debug a copy elsewhere |
| `K8S_UNAVAILABLE` | Anything the webhook could not decide, including a database error | Check the API pods' logs (`kubeadmission.*`) |

### The webhook secret

The chart generates the path secret into a Secret it owns (kept on uninstall, reused on upgrade, D969a), and the API stages it 0400 at start (D969b). The server re-reads it every minute. A GitOps tool that renders with `helm template` generates a new one on each render: the change in the `checksum/admission-webhook` annotation rolls the API pods, and until the new pods are ready, pods in enforced namespaces may be denied for a minute or two. They fail closed; nothing is admitted without a decision.

To rotate it on purpose, delete the chart's webhook Secret and `helm upgrade`. Cluster admins can read the secret (R-75); it only keeps others from calling the webhook.

### Rotate the admission TLS certificate

The API stages the admission certificate pair at pod start (an init container copies `admission-tls.crt` and `admission-tls.key` 0400 into the pod's memory, like `api.tls`, HR-371). The listener reloads the staged files when they change, but the staged copy only changes when a pod starts. So a rotated Secret takes effect when the API pods roll. Rolling them is the whole procedure: no refresher runs inside the pods, and nothing is admitted while a pod has no certificate.

**cert-manager.** With `admission.tls.certManagerCertificate` set, cert-manager renews the Secret and injects the new CA into the ValidatingWebhookConfiguration (`cert-manager.io/inject-ca-from`).

1. Watch for the renewal: `kubectl -n <ns> get certificate <name>` shows the new `notAfter`.
2. Roll the API pods: `kubectl -n <ns> rollout restart deployment/<release>-pantherclaw-api`, then `kubectl -n <ns> rollout status …`.
3. Check: start an agent pod. Admission still decides it.

cert-manager renews well before expiry (by default at two thirds of the lifetime), so a roll in the following days is in time. To have it happen without a person, add a reloader that restarts the deployment when the Secret changes.

**A Secret you manage.** With `admission.tls.caBundle`:

1. If the new certificate has the same CA: replace the Secret's `tls.crt` and `tls.key` (`kubectl create secret tls … --dry-run=client -o yaml | kubectl apply -f -`), then roll the API pods as above.
2. If the CA changes: first set `admission.tls.caBundle` to the old and the new CA concatenated and `helm upgrade`, so the API server accepts both; then replace the Secret and roll the API pods; then set `caBundle` to the new CA alone and `helm upgrade` again.

The `checksum/admission-webhook` annotation covers the webhook secrets, not the TLS Secret, so changing only the TLS Secret never rolls the pods by itself. If the certificate expires before the roll, the API server cannot call the webhook and denies every pod in enforced namespaces until the roll; running pods are unaffected.

## 2. Gateway enrolment in the cluster

An in-cluster gateway enrols from its own projected token (audience `pantherclaw-gateway:<org>`) instead of a `pcg_` token (HR-739, F1024).

1. Create the gateway (`pclaw gateway create`) and note its id and the CA pin from its enrollment page (`gateway.caSHA256`).
2. Bind it to the gateway's service account: `GatewayService.SetGatewayKubernetesBinding` with the cluster, namespace, service-account name and UID, and optionally the gateway image digests. It needs `gateways.manage` and writes `gateway.kubernetes_binding_set`.
3. Set `gateway.enabled`, `gateway.org`, `gateway.caSHA256`, `gateway.tls.existingSecret` and `gateway.service.clusterIP`, and `helm upgrade`. Each replica enrols at start through TokenReview against the bound cluster; its identity directory is an emptyDir, so a restarted replica enrols again with a fresh token.

Each projected token enrols once (single-use jti, D968a). Enrolment is refused, with one generic `GATEWAY_ENROLLMENT_REFUSED`, when the binding is missing or ambiguous (two gateways bound to the same service account), TokenReview does not return the bound username and UID, the pod is not Running with exactly one app container, or its image is not a bound digest. To stop in-cluster enrolment, clear the binding (`ClearGatewayKubernetesBinding`, audited `gateway.kubernetes_binding_cleared`); only `pcg_` tokens enrol that gateway afterwards. Revoking the gateway revokes its replicas' certificates as usual ([gateway.md](gateway.md)).

## 3. Closures

The chart runs a daily probe CronJob in each agent namespace and a control twin in the release namespace, with a `pantherclaw-canary` Deployment and Service there.

- The **control** run, outside every enforced namespace, checks that each probe's target answers (the positive twins).
- The **probe pod** in the agent namespace tries the API server, the kubelet, the node, metadata, cluster and external DNS, direct HTTPS, another Service and IPv6, each expected unreachable, plus the edge's two controls (a mapped host through the edge, an unmapped one refused). It posts its report to its edge's loopback `/__pc/report`, which signs it with the pod's workload key and submits it with `KubernetesService.SubmitClosure` (HR-738).

The server accepts a report only from an L2 instance enrolled by Kubernetes attestation, for the namespace it was attested in, with a fresh single-use nonce and the pod's edge and probe digests on the admission lists, read from the cluster, not from the report (HR-741). It adds its own two checks (HR-742):

- `admission_enforced`: this server decided a pod of the namespace within 24 hours;
- `netpol_egress_gateway_only`: the namespace's NetworkPolicies, read with the reviewer token, allow egress only to the gateway and the api on numbered TCP ports, never port 53.

A kind closes only when every probe was unreachable with its twin reachable, the edge's controls passed and both checks are ok. A passing closure is recorded per connection whose agent hosts the edge mediated, and expires after 24 hours (HR-743).

### Read and act on a failed closure

The submit answer and the coverage record list the failed probes and checks.

| Failed | Likely cause | Fix |
| --- | --- | --- |
| a probe reachable | The CNI ignores NetworkPolicy, or another policy in the namespace allows more | Use a CNI that enforces it; remove the wider policy |
| `netpol_egress_gateway_only` | A policy allows every peer, a port range, DNS, another component, or a wide ipBlock | Keep only the chart's policy shape (`apiEgressCIDRs` of at most /24 or /64 for an external server) |
| `admission_enforced` | The webhook decided no pod of the namespace for a day: it is not configured, or the namespace labels changed | Check the namespace labels and the ValidatingWebhookConfiguration |
| no twin | No passing control closure for the cluster | Check the control CronJob's logs in the release namespace |
| `K8S_CLOSURE_REJECTED` on submit | The probe or edge digest is not on the lists, the nonce was used or expired, or the signer's pod is gone | Update `admission.probeImageDigests` after a probe upgrade; rerun the job |
| `K8S_NOT_KUBERNETES_INSTANCE` | The probe pod's instance is not an admitted L2 Kubernetes instance, or its entry is no longer active | Check the probe service account's issuer entry |

To rerun the probe now: `kubectl -n <agent ns> create job --from=cronjob/pantherclaw-probe probe-manual-1`.

### Pod runs

At start the edge asks for its pod's run with `KubernetesService.StartPodRun` (HR-744, D973a). The run starts only under the issuer entry's run grant, for the pod name the instance was attested with, with the instance as launcher through the entry. An entry without a run grant gives `K8S_NO_RUN_GRANT`, and the edge then forwards nothing. The run's principal is the grant's (a user or service account). Set the grant with `pclaw issuer propose-kubernetes --run-grant`, which an Identity Publisher activates like any other change to the entry.
