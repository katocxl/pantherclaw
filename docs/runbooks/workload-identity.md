# Workload identity (PAP/1)

**Milestone:** M3 · **Owner:** the org's Identity Publisher and agent owners · **Status:** tested procedure (M3 end-to-end tests)

How an agent's workload gets an identity PantherClaw can verify: enrollment with an owner's token, or L2 attestation from GitHub Actions or Kubernetes. Background: [PAP-1](../protocol/PAP-1.md) §3–§5, [ADR-0018](../adr/0018-federated-workload-identity-and-represented-principals.md), [g0/M3.md](../g0/M3.md).

## 1. Enroll with an owner's token (any workload)

1. The owner creates the agent and a single-use enrollment token (15 minutes):
   ```bash
   pclaw agent create --name coder --team <team> --env <env> --owner <user> --context service
   pclaw agent enroll-token <agent> --out enroll.token
   ```
2. On the workload, create a key (it never leaves the machine) and enroll:
   ```bash
   pclaw workload init --key-file workload.json
   pclaw workload enroll --key-file workload.json --server https://pantherclaw.example.com --enrollment-token-file enroll.token
   ```
   The command prints the instance id and the key fingerprint.
3. The owner compares the fingerprint through a separate channel, then admits the instance:
   ```bash
   pclaw instance admit <instance> --fingerprint <fingerprint>
   ```
4. The workload gets 10-minute workload tokens with `pclaw workload token --key-file workload.json` and signs every request (the PantherClaw clients do this; see `internal/identity/workloadclient`).

A reused or expired enrollment token is refused and audited. A wrong fingerprint is refused: admit nothing you cannot match.

### Long-running services (`pclaw workload renew`)

A workload token is valid for 10 minutes. A service that runs longer keeps one with `pclaw workload renew` ([brief](../g0/M3-workload-renewal.md)):

```bash
pclaw workload renew --key-file workload.json --out workload.token [--kubernetes-token FILE | --github]
```

- It writes the token to `--out` and replaces it halfway through each token's lifetime. Each token goes to a new 0600 file that is renamed over the old one, so a reader never sees half a token. The service reads the file each time it builds a request, and signs the request with the key file as before: the token is useless without the key.
- Put both files in a directory only the service's user can write (`/run/<service>`, or a memory-backed `emptyDir` in a pod). On Windows the files inherit the folder's ACL.
- It opens no listener and never prints the token. Each renewal writes one line to stderr with the level and the expiry.
- Failures (server unreachable or restarting) are retried after 1 s, doubling up to 30 s, and the current token stays in the file meanwhile. Each failure is reported with the time the current token expires.
- With `--kubernetes-token` it re-attests only after the kubelet has rotated the projected token, because each one can be used once; the token the pod enrolled with is already used, so the first renewal reports a refused attestation and continues without it. With `--github` it re-attests at every renewal. Without a fresh attestation the instance stays L2 until its last attestation expires, then drops to L1; a level change is reported.
- The kill switch does not stop renewal: it stops actions, not identity, and the gateway refuses each action with `kill_switch`.

| Exit code | Meaning |
|---|---|
| 0 | Stopped (SIGINT, SIGTERM, Ctrl-C). The token stays in the file until it expires; a restarted renewer replaces it. |
| 1 | It could not run: an unreadable key file, an unwritable `--out`, an unenrolled key. |
| 2 | Wrong arguments. |
| 3 | The server refused renewal for good, and the token file was removed. `instance_not_admitted`: the instance was revoked, rejected or never admitted, or its agent is suspended or retired (`pclaw instance get`, `pclaw agent get`). `key_mismatch`: the key file is not the instance's key; enroll the new key as a new instance. `invalid_token`: the server does not know the instance. Do not restart; fix the cause first. |

A systemd unit for a service that runs as `billing`:

```ini
[Service]
User=billing
RuntimeDirectory=billing
RuntimeDirectoryMode=0700
RuntimeDirectoryPreserve=yes
ExecStart=/usr/local/bin/pclaw workload renew --key-file /etc/billing/workload.json --out /run/billing/workload.token
Restart=on-failure
RestartPreventExitStatus=3
```

In a pod, run it as a native sidecar (Kubernetes 1.29 or later: an init container with `restartPolicy: Always`, so it starts before the agent and stops after it). It shares a memory-backed volume with the agent and runs as the same user:

```yaml
spec:
  securityContext: {runAsUser: 10001, runAsGroup: 10001, fsGroup: 10001}
  initContainers:
    - name: pantherclaw-renew
      image: <an image with pclaw>
      restartPolicy: Always
      args: [workload, renew, --key-file, /var/run/agent/workload.json, --out, /var/run/pantherclaw/workload.token,
             --kubernetes-token, /var/run/secrets/pantherclaw/token]
      volumeMounts:
        - {name: agent-key, mountPath: /var/run/agent, readOnly: true}
        - {name: pantherclaw-run, mountPath: /var/run/pantherclaw}
        - {name: pantherclaw-token, mountPath: /var/run/secrets/pantherclaw, readOnly: true}
  containers:
    - name: agent
      volumeMounts:
        - {name: agent-key, mountPath: /var/run/agent, readOnly: true}
        - {name: pantherclaw-run, mountPath: /var/run/pantherclaw, readOnly: true}
  volumes:
    - {name: pantherclaw-run, emptyDir: {medium: Memory}}
    # agent-key holds the enrolled key file (§3 step 4); pantherclaw-token is the projected token (§3 step 4)
```

### Desktop MCP clients (`pclaw mcp proxy`, M6)

An MCP client on a developer's machine (an IDE or a desktop assistant) reaches a gateway connection through `pclaw mcp proxy`. The client starts the proxy as a stdio MCP server. The proxy signs every request with the enrolled desktop key (L1, HR-092) in the run you give it, and posts it to the gateway's `/mcp/{connection}`. It never opens a listener, so nothing else on the machine can borrow the workload's identity through it. Its diagnostics go to stderr. Configure the client like this:

```json
{"mcpServers": {"payments": {"command": "pclaw", "args": ["mcp", "proxy", "--gateway", "https://gateway.example.com",
  "--connection", "payments", "--key-file", "/home/dev/.pantherclaw/workload.json", "--run", "<run id>"]}}}
```

The proxy renews the workload token halfway through each token's lifetime, with the same renewer as `pclaw workload renew` (below). It speaks MCP 2026-07-28 or 2025-11-25, whichever the client does, and opens a new 2025-11-25 session by itself when the gateway ends one. Held calls come back as tasks when the client supports them (G0 M6 design decision 15).

## 2. GitHub Actions (L2)

1. An admin proposes an entry that pins the repository and owner **ids** (never names) and the workflow refs:
   ```bash
   pclaw issuer propose-github --agent <agent> --repository-id 123456 --owner-id 7890 \
     --workflow-ref octo-org/agent-repo/.github/workflows/agent.yml@refs/heads/main \
     --auto-admit --reason "CI agent"
   ```
   Find the ids with `gh api repos/OWNER/REPO --jq '.id, .owner.id'`. For a reusable workflow use `--job-type reusable-workflow` and pin `--workflow-sha`.
2. A person with the **Identity Publisher** role reviews what the proposal widens and activates it (`pclaw issuer activate ENTRY REVISION`; add `--confirm-reusable-refs-protected` for reusable workflows after checking that each ref is a protected branch or tag of its repository).
3. In the workflow (on a protected branch or tag; the preset refuses `pull_request`, `pull_request_target` and any `refs/pull/` ref):
   ```yaml
   permissions:
     id-token: write
     contents: read
   steps:
     - run: pclaw workload init --key-file "$RUNNER_TEMP/workload.json"
     - run: pclaw workload enroll --key-file "$RUNNER_TEMP/workload.json" --server "$PANTHERCLAW_SERVER" --github --org "$PANTHERCLAW_ORG"
   ```
   With `--auto-admit` active the instance is admitted at once; otherwise it waits for the owner. To stay at L2, renew with `pclaw workload token --github`.

### Agents that must look at pull requests (founder decision 1)

Do not run the agent **in** the pull request. Run it from a workflow on the protected branch that reads the pull request as data, triggered by a maintainer:

```yaml
on:
  issue_comment:
    types: [created]
jobs:
  review:
    if: github.event.issue.pull_request && startsWith(github.event.comment.body, '/review') &&
        contains(fromJSON('["OWNER","MEMBER","COLLABORATOR"]'), github.event.comment.author_association)
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      pull-requests: write
      contents: read
    steps:
      - uses: actions/checkout@v5   # checks out the default branch: the bot's own reviewed code
      - run: ./review-bot --pr "${{ github.event.issue.number }}"   # reads the PR through the API, as untrusted data
```

A label (`pull_request` with `types: [labeled]` cannot be used: it runs the PR's code) or a `workflow_run` trigger works the same way. The pull request's content is untrusted input; the bot's authority comes only from its grants (M4).

## 3. Kubernetes (L2)

1. The operator lists each cluster in the server configuration; tenants can only name these:
   ```json
   "identity": {"kubernetes_clusters": [{
     "name": "prod", "api_server": "https://10.0.0.1:6443", "ca_file": "/etc/pantherclaw/prod-ca.pem",
     "token_file": "/etc/pantherclaw/prod-reviewer.token", "allowed_prefixes": ["10.0.0.0/24"],
     "orgs": ["<org id>"]
   }]}
   ```
2. In each cluster, give PantherClaw's reviewer account exactly this (TokenReview, and `get` on pods in the namespaces that entries pin; nothing else):
   ```yaml
   apiVersion: v1
   kind: ServiceAccount
   metadata: {name: pantherclaw-reviewer, namespace: pantherclaw}
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: ClusterRoleBinding
   metadata: {name: pantherclaw-reviewer-tokenreview}
   roleRef: {apiGroup: rbac.authorization.k8s.io, kind: ClusterRole, name: system:auth-delegator}
   subjects: [{kind: ServiceAccount, name: pantherclaw-reviewer, namespace: pantherclaw}]
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: Role
   metadata: {name: pantherclaw-pod-reader, namespace: agents}
   rules: [{apiGroups: [""], resources: [pods], verbs: [get]}]
   ---
   apiVersion: rbac.authorization.k8s.io/v1
   kind: RoleBinding
   metadata: {name: pantherclaw-pod-reader, namespace: agents}
   roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: pantherclaw-pod-reader}
   subjects: [{kind: ServiceAccount, name: pantherclaw-reviewer, namespace: pantherclaw}]
   ```
   Create the reviewer token with `kubectl -n pantherclaw create token pantherclaw-reviewer --duration 24h` and replace the file before the token expires. The server reads `token_file` again every minute, so a new token needs no restart. Replace the file in one step (write a new file and rename it over the old one): while the file is empty or unreadable, the server keeps using the token it read last.
3. Propose and activate an entry that pins the namespace, the service account **name and UID** (`kubectl -n agents get sa coder -o jsonpath='{.metadata.uid}'`), and optionally image repositories or digests:
   ```bash
   pclaw issuer propose-kubernetes --agent <agent> --cluster prod --namespace agents --service-account coder \
     --service-account-uid <uid> --image-repository ghcr.io/acme/agent --auto-admit --reason "pod agent"
   ```
4. Give the pod a projected token with the org's audience (at most one hour) and enroll with it:
   ```yaml
   volumes:
     - name: pantherclaw-token
       projected:
         sources:
           - serviceAccountToken: {path: token, audience: "pantherclaw:<org id>", expirationSeconds: 3600}
   ```
   ```bash
   pclaw workload enroll --key-file /var/run/agent/workload.json --server "$PANTHERCLAW_SERVER" \
     --kubernetes-token /var/run/secrets/pantherclaw/token --org <org id>
   ```
   The image digest PantherClaw records is the pod's, read from the API server; a digest the workload reports is only `declared`.

## 4. GitLab CI (L2, M17)

1. The operator lists the GitLab instances PantherClaw trusts. With none configured, only `https://gitlab.com` is trusted, for every org. A self-managed instance must be listed; a tenant can never name one of its own:
   ```json
   "identity": {"gitlab_issuers": [
     {"issuer": "https://gitlab.com"},
     {"issuer": "https://gitlab.example.com", "ca_file": "/etc/pantherclaw/gitlab-ca.pem",
      "allowed_prefixes": ["10.0.2.0/24"], "orgs": ["<org id>"]}
   ]}
   ```
   `orgs` limits which orgs may pin the instance (every org when omitted); `allowed_prefixes` are the private ranges its address may resolve to.
2. An admin proposes an entry that pins the project and namespace **ids** (never paths) and the pipeline definitions (`ci_config_ref_uri`), and a person with the **Identity Publisher** role activates it:
   ```bash
   pclaw issuer propose-gitlab --agent <agent> --project-id 20 --namespace-id 72 \
     --ci-config-ref-uri gitlab.com/acme/agents/runner//.gitlab-ci.yml@refs/heads/main \
     --auto-admit --reason "CI agent"
   ```
   Find the ids on the project's overview page (Project ID) and the group's page (Group ID). The preset refuses tokens from unprotected refs and from `merge_request_event` or `external_pull_request_event` pipelines, whatever the entry says.
3. In the job, request an ID token with the org's audience and enroll with it. **Keep the job timeout at 60 minutes or less**: GitLab sets the token's lifetime from the job timeout, and PantherClaw refuses attestation tokens that live longer than one hour (HR-143).
   ```yaml
   agent:
     timeout: 60m
     id_tokens:
       PANTHERCLAW_ID_TOKEN:
         aud: pantherclaw:<org id>
     script:
       - pclaw workload init --key-file "$CI_BUILDS_DIR/workload.json"
       - pclaw workload enroll --key-file "$CI_BUILDS_DIR/workload.json" --server "$PANTHERCLAW_SERVER" --gitlab-token-env PANTHERCLAW_ID_TOKEN
   ```
   Each ID token attests once. A job has one, so L2 lasts until that token expires; `pclaw workload renew` keeps renewing at L1 afterwards.

## 5. SPIFFE JWT-SVIDs (L2, M17)

1. The operator lists the SPIFFE trust domains PantherClaw trusts, each with its JWT-SVID bundle from a SPIFFE bundle endpoint (`https_web`) or a JWKS file. With none configured the preset refuses every attestation; a tenant can never supply a bundle:
   ```json
   "identity": {"spiffe_trust_domains": [
     {"trust_domain": "prod.acme.example", "bundle_url": "https://spire.acme.example/bundle",
      "ca_file": "/etc/pantherclaw/spire-ca.pem", "orgs": ["<org id>"]},
     {"trust_domain": "edge.acme.example", "bundle_file": "/etc/pantherclaw/edge-bundle.json"}
   ]}
   ```
   Only keys with `use` `jwt-svid` and a `kid` are kept. A bundle file is read when the server starts.
2. An admin proposes an entry that pins the workload's **exact** SPIFFE ID (no prefixes or patterns) for a `service` agent, and an **Identity Publisher** activates it:
   ```bash
   pclaw issuer propose-spiffe --agent <agent> --trust-domain prod.acme.example \
     --spiffe-id spiffe://prod.acme.example/ns/agents/sa/runner --auto-admit --reason "service agent"
   ```
   The token's `sub` must be in the trust domain whose bundle verified it, and its audience exactly `pantherclaw:<org id>`.
3. Have the workload write a JWT-SVID for that audience to a file (for example with spiffe-helper), and pass it to `enroll`, `token` or `renew`:
   ```bash
   pclaw workload renew --key-file workload.json --out token.json --spiffe-token /run/spiffe/pantherclaw.jwt
   ```
   The file is read again at each renewal. Each JWT-SVID attests once; keep its lifetime at one hour or less (HR-143).

## 6. Google Cloud (L2, M17)

1. Nothing to configure on the server: Google ID tokens are verified only with Google's keys at `https://www.googleapis.com/oauth2/v3/certs`, and their issuer must be `https://accounts.google.com`.
2. An admin proposes an entry for a `service` agent that pins the service account's **numeric unique id** (never its email, which can be deleted and recreated), optionally with the Compute Engine project and instance, and an **Identity Publisher** activates it:
   ```bash
   pclaw issuer propose-gcp --agent <agent> --service-account-id 113524806285125460987 \
     --project-id acme-prod --auto-admit --reason "service agent"
   ```
   The unique id is shown as **Unique ID** on the service account's details page, or by `gcloud iam service-accounts describe EMAIL --format 'value(uniqueId)'`.
3. On the instance, attest with `--gcp`: pclaw asks the metadata server for an ID token with audience `pantherclaw:<org id>` and the Compute Engine claims (`format=full`), in the same way as `--github` (section 2).
   ```bash
   pclaw workload renew --key-file workload.json --out token.json --gcp
   ```

## 7. AWS (L2, M17)

1. The workload never sends AWS credentials. It signs an `sts:GetCallerIdentity` request with SigV4, including the signed header `X-Pantherclaw-Audience: pantherclaw:<org id>`, and PantherClaw sends that request to STS itself. STS's answer says which role session signed it. By default the request may go only to the global and regional `sts.*.amazonaws.com` endpoints; to list the endpoints explicitly (for example only your regions):
   ```json
   "identity": {"aws_sts_hosts": ["sts.eu-west-1.amazonaws.com", "sts.us-east-1.amazonaws.com"]}
   ```
2. An admin proposes an entry for a `service` agent that pins the account and the IAM role name, and an **Identity Publisher** activates it. Only sessions of that role attest; IAM users never do.
   ```bash
   pclaw issuer propose-aws --agent <agent> --account-id 123456789012 --role-name agent-runner \
     --auto-admit --reason "service agent"
   ```
3. Attest with `--aws`. pclaw signs with the role session credentials in `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` (for example from `eval "$(aws configure export-credentials --format env)"`), on the regional endpoint of `AWS_REGION` when it is set:
   ```bash
   pclaw workload renew --key-file workload.json --out token.json --aws
   ```
   A signed request attests once, within 15 minutes of signing; pclaw signs a new one at each renewal.

## 8. When something goes wrong

- **Disable an entry** at once: `pclaw issuer disable ENTRY --reason …`. It stops auto-admission, and its instances drop to L1 at their next token.
- **Revoke an instance**: `pclaw instance revoke INSTANCE --reason …`. Outstanding permits fail at `BeginDispatch`.
- **Unknown keys** reaching the gateway appear as discovered agents (`pclaw agent list --state discovered`); claim, merge or retire them. A `security.discovery_flood` audit event means the per-gateway rate or the per-org cap was reached.
- **Network change alerts** (`security.instance_network_changed`) mean the same key was used from a new network: check whether the key was copied.
