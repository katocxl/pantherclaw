<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw Authority Protocol — PAP/1

**Status:** Draft 1 (2026-10-08; §3.3 and §5 revised 2026-10-09 for ADR-0018; §3.2–§5 clarified 2026-10-09 by the M3 G0 brief; §5 `PAP-Run-Id` added in M3 slice 13; §6–§8 and §10 clarified 2026-10-09 by the M6 G0 brief) · **License:** Apache-2.0 (this directory) · **Normative language:** MUST, MUST NOT, SHOULD, MAY per RFC 2119/8174.

PAP/1 defines how an AI agent workload proves *who it is*, how a run is bound to *whose authority* it uses, how a requested action is expressed *exactly*, and how authorization, dispatch and evidence are represented so that any party can verify them. It is open so that SDKs, gateways and target-side verifiers interoperate.

## 1. Roles

| Role | Description |
|---|---|
| **Workload** | One running agent instance (process/container/job). Holds a private key. |
| **Owner** | Human accountable for an agent; issues enrollment tokens and confirms key fingerprints. |
| **Launcher** | Human or service that starts a run. |
| **Represented principal** | The human/service whose authority the run uses. MAY differ from the launcher. |
| **Gateway (PEP)** | Enforcement point that mediates actions. |
| **Authority (PDP + finalizer)** | PantherClaw Transaction Authority: decides and finalizes. |
| **Target** | System where the effect happens. In *target-enforced mode* it verifies action tokens. |
| **Verifier** | Any party checking receipts offline. |

## 2. Cryptographic profile

| Use | Algorithm |
|---|---|
| Signatures (tokens, proofs, receipts, permits, checkpoints) | Ed25519 (JWS `alg: "EdDSA"`, `crv: "Ed25519"`). Receipts MAY carry an additional ML-DSA-65 signature (§9.4). |
| Hash | SHA-256, encoded base64url without padding unless stated. |
| Key thumbprint | RFC 7638 JWK thumbprint (SHA-256) = `jkt`. |
| Canonical JSON | RFC 8785 (JCS). |
| Sealed credentials | HPKE (RFC 9180) KEM `MLKEM768-X25519` (X-Wing), KDF HKDF-SHA256, AEAD AES-256-GCM. |
| Transport | TLS 1.3. Gateway↔Authority: mutual TLS. |

Implementations MUST pin algorithms per key (`kid`) and MUST reject `alg: none`, HMAC algorithms on asymmetric keys, and any algorithm not listed for that key.

## 3. Workload identity

### 3.1 Key generation
The workload MUST generate an Ed25519 key pair locally. The private key MUST NOT leave the workload. Implementations SHOULD use non-exportable hardware-backed storage (TPM, Secure Enclave) when available.

### 3.2 Enrollment
1. The Owner requests an **enrollment token** for `(org, agent, environment)`. Properties: random 256-bit secret, single use, TTL ≤ 15 minutes, stored by the Authority only as SHA-256.
2. The workload sends `EnrollWorkload{enrollment_token, public_jwk, attestation?, declared_release?}` signed with its private key (proof of possession over a server-provided challenge).
3. The Authority creates an **agent instance** in state `PENDING_ADMISSION` and an `ADMISSION` waitlist entry showing the key fingerprint. The Owner MUST confirm the fingerprint (or an attestation policy auto-admits L2+ instances that match pinned claims).
4. On admission the instance becomes usable; until then requests are `CANNOT_AUTHORIZE` (or observed only in monitor mode).
5. **Automatic admission (L2).** A workload whose attestation token matches an active trusted-issuer entry that allows automatic admission MAY enroll without an enrollment token: the token's audience names the org, the entry names the agent, and the instance is admitted at once. The attestation token is consumed (single use).

### 3.3 Attestation levels
| Level | Evidence | Notes |
|---|---|---|
| L1 | Enrollment token + Owner fingerprint confirmation | Desktop workloads (`pclaw mcp proxy`) are capped at L1. |
| L2 | Workload token from a **trusted issuer** configured for the org. Presets: GitHub Actions OIDC token; Kubernetes projected service-account token (validated via TokenReview) + image digest | Every issuer entry MUST pin the issuer, key source, audience (`pantherclaw:<org_id>`), allowed algorithms and at least one immutable claim binding the token to one agent; an entry without one MUST be rejected. Rules built into a preset MUST NOT be disabled by configuration. GitHub: MUST match `repository_id` and `repository_owner_id`; MUST require `ref_protected` to be `true` (the triggering ref is a protected branch or tag); MUST reject tokens whose `event_name` is `pull_request` (from forks or the same repository) or `pull_request_target`, because those runs execute code not yet reviewed into a protected ref; any `ref` under `refs/pull/` (for example a `pull_request_review` run) MUST be rejected too. The workflow binding depends on the job type, and each issuer entry declares which it accepts: an ordinary workflow job binds on `workflow_ref` (workflow path and ref); a job that calls a reusable workflow binds on `job_workflow_ref` (the called workflow's path and ref, which MUST itself be a protected branch or tag of its repository). An entry MAY also pin `workflow_sha` or `job_workflow_sha` to one exact revision. Kubernetes: the projected token MUST carry the entry's audience and be validated through TokenReview, which MUST return the bound pod's name and UID; the entry pins the cluster, namespace and service account (name and UID, so a recreated account with the same name does not match). The image digest MUST come from trusted cluster state for that pod UID (the API server's `status.containerStatuses[].imageID`) or from signed evidence bound to that pod, such as a verified image signature or admission attestation; a digest the workload supplies itself is only `declared`. Each attestation token is single use (`jti`, or the token's SHA-256 when it has none), MUST expire at most 1 hour after issue, and confers L2 only until it expires; the workload re-attests with a fresh token, and a workload token never outlives the attestation behind its level. Further presets (GitLab CI, cloud workload identity, SPIFFE JWT-SVID, Microsoft Entra Agent ID) are future. |
| L3 | SPIFFE X.509 SVID / cloud instance identity | Future. |

Release identity (code hash, image digest) is recorded as `declared` unless supplied by L2+ attestation, then `attested`. A value the workload reports about itself is always `declared`, whatever its attestation level.

### 3.4 Workload token
Issued by the Authority after admission; JWS compact, header `{"alg":"EdDSA","kid":"<authority key id>","typ":"pap-wt+jwt"}`:

```json
{
  "iss": "https://<authority>",
  "sub": "pc:org/<org_id>/agent/<agent_id>/inst/<instance_id>",
  "aud": "pantherclaw-gateway",
  "iat": 1791457200, "nbf": 1791457200, "exp": 1791457800,
  "jti": "<uuidv7>",
  "cnf": {"jkt": "<RFC 7638 thumbprint of workload key>"},
  "pap": {"v": 1, "org": "<org_id>", "env": "<env_id>", "att_lvl": 1, "release": {"state": "declared", "digest": "sha256:…"}}
}
```

TTL MUST be ≤ 10 minutes. Refresh requires a fresh request proof.

## 4. Request proof (DPoP profile)

Every request from a workload MUST carry `Authorization: PAP <workload token>` and `PAP-Proof: <JWS>` signed with the workload key. Header `{"alg":"EdDSA","typ":"pap-proof+jwt","jwk":{…public key…}}`; claims:

| Claim | Meaning |
|---|---|
| `htm`, `htu` | HTTP method and target URI (scheme, host, path; no query/fragment) |
| `iat` | Issued-at (seconds) |
| `jti` | Unique id (≥ 128 bits) |
| `ath` | base64url(SHA-256(workload token)) |
| `bh` | base64url(SHA-256(raw request body bytes)) — computed **before** any parsing |
| `nonce` | Most recent server-issued nonce (`PAP-Nonce` response header) |

Verification order (MUST): (1) verify workload token signature, `iss`, `aud`, `exp/nbf`; (2) verify proof signature with the embedded `jwk`; (3) check `jkt(jwk) == cnf.jkt`; (4) check `htm/htu/ath/bh`; (5) check `nonce` is current (server-issued, ≤ 5 min); (6) **then** insert `(jkt, jti)` into the replay store (unique, retained ≥ nonce lifetime + 60 s). Failure at any step: HTTP 401 with `PAP-Error` code (§12) and, where applicable, a fresh `PAP-Nonce`.

A nonce MAY be shared by all workloads of an org (RFC 9449 permits shared nonces). Verifiers compare `htu` with their own configured public URL, never with the request's `Host` header.

**Key-only proofs.** Some requests carry `PAP-Proof` without `Authorization` and without `ath`:
- enrollment (§3.2);
- workload-token issuance and refresh (§3.4);
- requests from workloads that hold no workload token.

Verification order (MUST): (1) verify the proof signature with the embedded `jwk` (EdDSA only); (2) check `htm/htu/bh`; (3) check `nonce` is current; (4) **then** insert `(jkt, jti)` into the same replay store as above. A proof that fails any step is not recorded.

A key-only proof shows possession of a key, never an identity:
- enrollment binds the key through an enrollment token or an attestation token;
- token issuance requires `jkt` to equal the registered key of the named admitted instance.

Any other request with a key-only proof, or with a key that is not an admitted instance, carries no identity. It is refused and MAY be recorded as a discovery.

## 5. Runs

A **run** is created by the Authority (never by the workload) via `StartRun{agent_id, instance_id?, launcher, represented_principal, grant_id | task template, task_ref}` called by an authenticated launcher (human session, service account, or automation identity). The Authority returns a server-minted `run_id` bound to: instance (or instance set), launcher, represented principal and grant. Workloads reference `run_id`; any mismatch with the bound instance ⇒ `DENY` (tamper). Over HTTP a workload names its run in the `PAP-Run-Id` request header; the gateway copies it into the ActionIR, and the Authority checks it against the verified instance (`run_mismatch` otherwise). A run created without an instance binds to the first admitted instance of its agent that uses it. The represented principal is the launcher itself, a user proven by a subject token (below), or for a child run the parent run's principal; a principal merely named by the launcher MUST be rejected. A workload in an active run MAY start a **child run**: it inherits the represented principal, records the parent instance as its launcher, and MUST NOT outlive its parent. An Authority that does not yet issue grants creates runs without one and MUST reject a `StartRun` that names a grant or task template. A run never selects its own grant.

**Represented principal from the customer's identity provider.** When the launcher is not the represented principal (for example a service that starts a run for a signed-in user), `StartRun` MAY carry `subject_token` and `subject_token_type` with RFC 8693 semantics, issued to that user by an OIDC provider configured for the org: either an OIDC ID token or an access token that is a signed JWT (RFC 9068 profile) carrying `iss`, `sub`, `aud`, `exp` and `iat`. Opaque access tokens MUST be rejected; PAP/1 defines no introspection path. The launcher is the actor. The Authority MUST verify the signature, issuer, audience (MUST name the Authority), expiry and freshness (`iat` ≤ 5 minutes old), MUST reject a replayed token (keyed on `jti`, or on the token's SHA-256 when it has none), and MUST link `(iss, sub)` to a user of the org. The run records the provider identity and the actor chain. A subject token proves who is represented; it MUST NOT create, widen or substitute for a grant.

## 6. ActionIR v1 — the canonical action

ActionIR is produced by the gateway (or SDK, for cooperative mode) from a raw tool call using an **ACTIVE, signed tool package**. Schema (all fields required unless marked optional):

```json
{
  "v": 1,
  "org": "<org_id>", "env": "<env_id>",
  "run_id": "<server-minted>", "action_id": "<uuidv7, stable across retries of the same logical action>",
  "agent_instance": "<instance_id>",
  "operation": "payments.refund.create",
  "definition": {"package": "pc.mock-payments", "version": "1.0.0", "digest": "sha256:…"},
  "channel": "mcp | http | sdk | hook",
  "route": "<route_id>",
  "connection": "<connection_id, optional>",
  "target": {"type": "payments.charge", "id": "ch_3Px…", "account": "acct_…"},
  "params": {"amount": {"value": "85.00", "currency": "USD"}, "reason": "duplicate"},
  "destinations": [{"kind": "external", "id": "…"}],
  "dedupe_key": "refund:order_714"
}
```

Rules (MUST):
- **Strict parsing:** reject duplicate object keys, invalid UTF-8, unknown fields, nesting depth > 16, strings > 8 KiB (material) / 64 KiB (other), total > 1 MiB.
- **No JSON numbers in material parameters.** Amounts are decimal strings matching `^-?(0|[1-9][0-9]{0,17})(\.[0-9]{1,8})?$`; currencies are ISO-4217 uppercase.
- **Identifiers** (target ids, accounts, recipients): reject mixed-script/confusable strings and bidi controls; never case-fold or Unicode-normalize bytes that are meaningful to the target (git refs, file paths, object keys).
- **No defaults:** an ambiguous target, missing material field or unsupported unit ⇒ `CANNOT_AUTHORIZE` (never a silent default).
- **Canonical hash:** `action_hash = SHA-256(JCS(ActionIR))`.
- **Dedupe key:** irreversible operations declare a semantic dedupe key in the tool package; an open `UNKNOWN` or recent success on the same key parks a new request in `RECONCILIATION`.
- **Connection:** a gateway sets `connection` to the registered connection the request came through (channels `http`, `mcp` and `hook`). The Authority MUST check that the calling gateway serves that connection and that `route` is one of its routes. Because `connection` is part of the action hash, a decision or approval never carries over to another target or credential. Actions from cooperative SDKs (`sdk`) MAY omit it.

## 7. Authorization exchange

### 7.1 Authorize
`Authorize{action: ActionIR, workload_token, proof, body_hash}` from gateway to Authority over mTLS. The Authority MUST re-verify §4 itself and MUST derive the org from the gateway certificate binding (reject mismatch). Response:

```json
{
  "decision": "ALLOW | ALLOW_WITH_OBLIGATIONS | REQUIRE_APPROVAL | REQUIRE_STEP_UP | DENY | CANNOT_AUTHORIZE",
  "transaction_id": "<uuidv7>",
  "action_hash": "…",
  "reasons": [{"code": "GRANT_AMOUNT_EXCEEDED", "check": "authority", "detail": "…", "decisive": true}],
  "obligations": [{"kind": "field_filter", "timing": "before_execution", "spec": {…}}],
  "wait": {"handle": "…", "retry_after_s": 5, "expires_at": "…"},
  "permit": "<JWS, only for ALLOW / ALLOW_WITH_OBLIGATIONS>",
  "receipt_ref": "…"
}
```

`obligations` lists only what the gateway applies. A policy's `verify` obligation (`{"kind": "verify", "level": "follow_up", "timing": "after_dispatch"}`) raises the level the effect must be verified at (§9.3); the Authority applies it, the decision receipt states it, and the gateway is never sent it. When the required level is above what the definition's verifier reaches, or the action's connection cannot make the verifier's reads, the decision is `CANNOT_AUTHORIZE` with `VERIFIER_UNSUPPORTED`.

Idempotency: `(org, run_id, action_id)` is unique. Same triple + same hash ⇒ the stored decision is returned. Same triple + different hash ⇒ `DENY` with code `ACTION_TAMPERED` and a security alert. `DENY` and expired decisions are terminal for that triple; `CANNOT_AUTHORIZE` MAY be retried.

**Monitor mode.** When the action's route runs in `monitor` mode, the response carries `"mode": "monitor"` and `decision` is hypothetical: the Authority records it, reserves nothing, and returns a permit whatever the decision, unless the identity or containment checks failed. In monitor mode the presence of a permit, not the decision, tells the gateway to dispatch; the permit still goes through `BeginDispatch`. Nothing about a monitor-mode action may be reported as prevented.

### 7.2 Dispatch permit
JWS, `typ: "pap-permit+jwt"`, TTL ≈ 5 s:

```json
{"iss": "…", "aud": "gw:<gateway_id>", "jti": "<permit_id>", "iat": …, "exp": …,
 "pap": {"v": 1, "org": "…", "txn": "<transaction_id>", "act": "<action_hash>",
         "epoch": 42, "approval": {"binding": "…", "assertion": "<WebAuthn assertion, high-consequence only>"}}}
```

### 7.3 BeginDispatch (commit point)
Before sending any byte to the target the gateway MUST call `BeginDispatch{permit_id, epoch, outbound_method, outbound_url, outbound_body_hash}`, after building the outbound request and before sending it. The Authority atomically transitions the permit `ISSUED → DISPATCHING` only if not expired (database clock) and `epoch` equals the org's current containment epoch. Any failure ⇒ the gateway MUST NOT dispatch. A permit that was `DISPATCHING` without a recorded outcome becomes `UNKNOWN` (never released automatically). For a target-enforced connection the response carries the action token (§10), minted over `outbound_body_hash`.

### 7.4 RecordExecution
`RecordExecution{permit_id, outcome: accepted|failed|unknown|delegated, target_response_digest, timings}` → execution receipt. The target-facing idempotency key (where the target supports one) MUST be derived from `transaction_id`, never from agent-supplied ids. `delegated` is used only by cooperative channels (hooks, SDK authorize), where the agent performs the allowed action itself: its reservations are committed as if the action happened, and the receipt says the gateway did not perform it.

`RecordExecution` MAY also carry `target_ref`: the identifier of the object the target created, which the gateway reads from a 2xx response at the place the action definition's verifier names (`verifier.reference`); it is the only part of a response body sent to the Authority, apart from payload captures under a capture profile. An `unknown` outcome opens a reconciliation task and keeps the reservations (§9.3). When the sweeper has already marked the permit `UNKNOWN`, a later `RecordExecution` for it is kept as evidence: `accepted` resolves the reconciliation as occurred, and any other outcome resolves nothing.

## 8. Holds, waiting and approvals

- `REQUIRE_APPROVAL` / `REQUIRE_STEP_UP` return `wait.handle`. SDKs MAY long-poll `Wait{handle}` or subscribe via SSE; MCP clients receive a structured pending result, or a task when they support one (the tasks extension of MCP 2026-07-28, or a task-augmented call in 2025-11-25).
- When the requirement is satisfied the workload **resubmits the same `run_id` + `action_id` with an identical action hash**. The Authority re-runs the full pipeline and finalizes only if the same requirement class is now satisfied. Polling an MCP task is such a resubmission: the gateway resubmits the held action with the polling request's own, freshly verified credentials, and only for the run, instance and connection that created the task.
- **Approval binding:**
  `binding = SHA-256(JCS({v, action_hash, effective_action_hash, decision_basis_digest, material_facts_digest, grant: {id, revision}, definition_digest, run_id, agent_instance, jkt, approver_requirements, expires_at, display_hash}))`
  where `display_hash` is the SHA-256 of the approval text rendered from the tool package's approval template (agent-supplied text is excluded and shown separately as untrusted).
  - `v` is `1`. `effective_action_hash` is the action after obligations clamp it (equal to `action_hash` when nothing is clamped), so the approver binds the action that will run. `grant` is the run's grant and its revision; the whole chain is inside the decision basis.
  - Hashes and digests are the base64url (no padding) of their 32 bytes. `expires_at` is RFC 3339 UTC in whole seconds. `approver_requirements` is the merged list, each `{kind, role, count, independent}` (approval) or `{kind, subject, method}` (step-up), approvals first by role, then step-ups by subject.
  - A restoration of a suspended agent binds `{v, subject: "agent.restore", agent_id, agent_change_seq, requested_state, requested_by, reason_hash, approver_requirements, expires_at, display_hash}`.
  - A batch approval's challenge is `SHA-256(JCS({v: 1, batch: [sorted bindings]}))`.
  - These fields are additive to the first version of this formula (§13). Golden vectors: `internal/approvals/domain/testdata/binding_vectors.json`.
- High-consequence approvals MUST be WebAuthn assertions with `challenge = binding` (user verification required). Approvals are accepted only from human sessions — never from API keys or service accounts. Two-person rules require two distinct users **and** distinct WebAuthn credentials.

## 9. Receipts and evidence

### 9.1 Decision receipt
Signed JWS (`typ: "pap-decision+jwt"`) containing: transaction id, action hash, decision, reasons, checklist, obligations, versions (decision-basis digest, grant revision, definition digest), facts digest, identity summary (instance, att_lvl, launcher, principal), timestamps, `simulated` flag.

### 9.2 Execution receipt
Signed JWS (`typ: "pap-execution+jwt"`, `jti` = permit id) containing: transaction id, effective action hash (`effective`), permit id, gateway id, connection, access mode (target-enforced, narrow temporary, PantherClaw-held, constrained runtime, agent-held), attempt number, dispatch time (`dispatched_at`), outcome, target status, target response digest, `target_ref` when the target returned one, who recorded it (`recorded_by`: `gateway`, or `sweeper` for a dispatch that never reported), `monitor` when applicable, `simulated` flag.

### 9.3 Effect receipt
Signed JWS (`typ: "pap-effect+jwt"`, `jti` = transaction id and sequence) appended for every change of a transaction's effect state, never rewritten. It contains: transaction id, sequence, the verifier (read operation, gateway, connection, what it `establishes`), the verification level required and achieved (`acceptance` · `follow_up` · `domain_effect` · `downstream`), the expected and observed values as digests, the result state (`CONFIRMED`, `NONE_CONFIRMED`, `PARTIAL`, `PROPAGATION_PENDING`, `CONFLICTING`, `UNVERIFIABLE`, `UNKNOWN`, `COMPENSATED`; ARCHITECTURE §6.2), one result per declared effect kind, the basis (observation ids, or the person who resolved a reconciliation), the definition's limits text, timestamps and the `simulated` flag. A target's acceptance, the executor's report and anything the agent says are never observations: on their own they reach only the `acceptance` level. An `unknown` outcome stays unresolved, with its reservations held, until an observation shows the effect happened (resolved automatically) or an independent person releases it with a WebAuthn assertion bound to the resolution.

### 9.4 Signatures and chaining
Receipts are Ed25519-signed; the format reserves `sigs[]` for an additional ML-DSA-65 signature. Receipts are linked into a per-org hash chain (`entry_hash = SHA-256(prev_hash ‖ JCS(entry))`) and summarized in signed Merkle checkpoints. A global root over all orgs MAY be anchored in a public transparency log.

- **Tree and checkpoints.** Each org's chain is an RFC 9162 Merkle tree whose leaves are the `entry_hash` values in sequence order, stored as C2SP tlog tiles. A checkpoint is a C2SP signed note: origin `<log origin>/org/<org id>`, tree size and base64 root, signed by the deployment's `checkpoints` Ed25519 key, and optionally co-signed with ML-DSA-65 under a separate key name that verifiers which do not know it ignore. That line uses the key name `<origin>/ml-dsa-65` and the unregistered signature type `0xff` followed by `pantherclaw.ml-dsa-65.v1`, so its key ID is the first 4 bytes of `SHA-256(key name ‖ 0x0A ‖ 0xff ‖ "pantherclaw.ml-dsa-65.v1" ‖ public key)`; the signature is pure ML-DSA-65 (FIPS 204) over the note text with the context string `pantherclaw.signed-note.v1`.
- **Anchors.** A global tree has one leaf per org per anchor, `SHA-256(0x00 ‖ "pantherclaw.anchor-leaf.v1" ‖ nonce ‖ SHA-256(checkpoint note))` with a fresh 32-byte nonce, so leaves reveal neither the org nor its activity. The statement `{"v":1,"type":"pantherclaw.anchor","origin":…,"period":…,"size":…,"root":…}` (JCS) is signed with the `anchors` key (ECDSA P-256), entered in a Rekor v2 log as a `hashedrekord` entry, and its signature is timestamped by an RFC 3161 authority. Logs and authorities are configuration, never fixed.
- **Verification.** A verifier checks receipts against keys it pinned from `evidence-keys.json` (§11), chain links, inclusion proofs to a checkpoint, consistency proofs between checkpoints (including one it saved earlier), the checkpoint signatures, the org's anchor leaf and its inclusion in the global root, the log's checkpoint and inclusion proof, and the timestamp. It reports each check as passed, failed or not available. Integrity of the evidence it was given is all a passing check shows: not completeness, not that an external effect happened. `pclaw verify` reads a `pantherclaw.bundle/v1` bundle (receipts; entries with seq, `prev_hash` and `entry_hash`, and a tombstone in place of a body removed by retention; checkpoints with inclusion and consistency proofs; an optional saved checkpoint; the anchor with its Rekor entry and DER `TimeStampResp`) and a `pantherclaw.trust/v1` trust file (the log origin, and per key its `kid`, purpose, algorithm, public key, validity and state). Public keys are encoded as the 32-byte Ed25519 key (EdDSA), PKIX DER (ES256), or the 1,952-byte FIPS 204 key (ML-DSA-65).
- **Export.** A deployment signs a checkpoint of each org whose chain grew, at most every few minutes, only after recomputing the new entries' links and proving the new tree consistent with the previous checkpoint, and re-verifies each org's whole chain and tiles daily. `EvidenceService.ExportBundle` builds a bundle of chosen transactions (their decision, execution and effect receipts and the chained entries that record them) or of a range of at most 1,000 entries (and the receipts they record). The bundle holds the latest checkpoint and an inclusion proof to it for every entry it covers. Entries that are newer than that checkpoint have no proof, and entries that are not chained yet are left out. Given the tree size of a checkpoint the requester saved earlier, the bundle also holds the consistency proof from that size to the latest checkpoint, and that checkpoint itself.

## 10. Target-enforced mode (action tokens)

For targets that run PantherClaw verifier middleware, the gateway attaches `PAP-Action: <JWS>`. The Authority mints it at `BeginDispatch` (§7.3) with its `action_tokens` key, published in the JWKS, over the outbound body hash the gateway reported; the audience is the connection the target is registered as:

```json
{"iss": "…", "aud": "<connection id>", "jti": "<single use>", "iat": …, "exp": "≤ 60 s",
 "pap": {"v": 1, "txn": "…", "act": "<action_hash>", "bh": "<SHA-256 of the exact outbound body>",
         "op": "payments.refund.create", "target": {"type": "…", "id": "…"}}}
```

The verifier MUST check signature (JWKS), `aud`, expiry, `bh` against the received body, single use of `jti` in a **shared** replay store, and that the requested operation/target match. Only then may the route be counted as `ENFORCED` for cooperative (SDK) modes.

## 11. Keys and discovery

- JWKS: `GET /.well-known/pantherclaw/jwks.json` (Authority signing keys, with `use`, `alg`, `kid`).
- Rotation every 90 days with ≥ 7-day overlap; revoked keys published in `/.well-known/pantherclaw/revoked-keys.json`: `{"format":"pantherclaw.revoked-keys/v1","issuer":…,"keys":[{"kid":…,"purpose":…,"algorithm":…,"revoked_at":…}]}`, every revoked key of a purpose that the JWKS or `evidence-keys.json` publishes.
- Evidence keys: `GET /.well-known/pantherclaw/evidence-keys.json` lists the keys that sign receipts (`receipts`), checkpoints (`checkpoints`, Ed25519, and the optional ML-DSA-65 co-signature, `checkpoints_pq`), anchors (`anchors`, ECDSA P-256) and evidence-pack manifests (`evidence_packs`), revoked ones included. The document has the members of a `pantherclaw.trust/v1` trust file under its own format, `pantherclaw.evidence-keys/v1`: `issuer` (the deployment's public URL), `log_origin`, and `keys`, each with `kid`, purpose, algorithm (`EdDSA`, `ES256` or `ML-DSA-65`, exactly one per purpose), `public_key` (the encodings of §9.4, standard base64), `not_before` (its creation, rounded down to the second), `not_after` (when it stopped signing, by becoming retiring or revoked, rounded up to the second; absent while active) and state (`ACTIVE`, `RETIRING` or `REVOKED`). Offline verifiers pin this document once and compare fingerprints through another channel; they never fetch keys while verifying (§9.4).
- Tool packages and licence keys are signed by separate offline roots (not in the JWKS).

## 12. Error codes (`PAP-Error`)

`invalid_token`, `token_expired`, `invalid_proof`, `proof_replay`, `use_nonce`, `key_mismatch`, `body_hash_mismatch`, `instance_not_admitted`, `attestation_insufficient`, `run_mismatch`, `action_tampered`, `unknown_route`, `definition_inactive`, `ambiguous_input`, `rate_limited`, `authority_unavailable` (→ `CANNOT_AUTHORIZE`).

## 13. Versioning

`pap.v` is a major version. Additive fields are allowed within v1; consumers MUST ignore unknown *claims* in tokens but MUST reject unknown *fields* in ActionIR. Breaking changes require PAP/2.

## 14. Security considerations (summary)

Replay is prevented by `(jkt, jti)` uniqueness, server nonces and single-use permits/tokens; token theft without the private key is useless; agents never receive target credentials; the gateway re-serializes outbound requests from ActionIR so parser differentials cannot smuggle unauthorized effects; the Authority never trusts gateway assertions about org or identity; cooperative modes are labeled honestly. See `docs/security/THREAT_MODEL.md` and `docs/security/HARDENING_RULES.md` in the PantherClaw repository.
