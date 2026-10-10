# Runbook — Gateways: enrollment, renewal, revocation, approver keys

**Milestone:** M6 · **Owner:** the org's gateway admins and the gateway operator · **Status:** tested procedure (M6 tests: enrollment, renewal, revocation, mTLS, approver keys)

A gateway is the customer-hosted enforcement point. It serves one org, reaches the Authority only over mutual TLS with a certificate from PantherClaw's internal CA, and holds the broker key that opens sealed credentials. Background: [g0/M6.md](../g0/M6.md) design decisions 1–3, 6 and 8, and founder decision 6; [HR-180, HR-181, HR-038](../security/HARDENING_RULES.md).

## 1. Server prerequisites

- The server's gateway listener is configured (`gateway_api` in the server config, `PC_GATEWAY_API_ADDR` for the address):
  - `addr`: the mTLS listener, for example `0.0.0.0:8443`;
  - `hostnames`: 1–16 names in its certificate;
  - `url`: the `https` URL gateways use, whose host is one of the `hostnames`.
- Without `addr` the listener is off and no gateway can work.
- At start the server logs `server.gateway_listener` with the CA's `ca_sha256`.
- Gateways reach `AuthorityService` and `GatewayService` (except `Enroll`) only there. The public API refuses them, whatever credential is sent.

## 2. Create a gateway and an enrollment token (gateway admin)

Needs `gateway.manage` (human only; the `gateway_admin` role). Output is JSON.

```bash
pclaw gateway create edge-eu-1                 # name: lower-case letters, digits and dashes
pclaw gateway enroll-token <gateway-id>        # token (pcg_…, shown once, valid 15 minutes), expire_time, ca_sha256, gateway_api_url
```

Give the operator the token, the `ca_sha256` pin and the URLs, through a channel an attacker cannot change. The pin is what protects enrollment: the gateway accepts the CA only if its SHA-256 equals the pin. A token used by someone else first makes the real enrollment fail visibly; revoke the gateway and start again. Replicas of one gateway each enroll with their own token and share the record, the broker key and the configuration.

## 3. Enroll and serve (gateway operator)

1. **Broker key**, if the gateway will hold sealed credentials (§5 of [key-rotation.md](key-rotation.md)):
   ```bash
   pantherclaw-gateway broker-key generate --out /etc/pantherclaw/broker.json --kek-file /etc/pantherclaw/kek
   ```
2. **Configuration** (`--config`, or `PC_GW_*` variables; example `deploy/dev/gateway.example.json`):

   | Key | Default | Notes |
   |---|---|---|
   | `listen` | `127.0.0.1:8090` | Must be loopback unless `tls.cert_file`/`tls.key_file` are set. |
   | `public_url` | `http://127.0.0.1:8090` | `scheme://host[:port]`: what agents call, and what PAP/1 proofs are checked against. |
   | `control.api_url` | `http://127.0.0.1:8080` | The server's public API (enrollment only); http only on loopback. |
   | `control.ca_sha256` | — | The pin (`sha256:` + 64 hex). |
   | `control.gateway_url` | — | Optional `https` override of the URL the server gave at enrollment. |
   | `control.identity_dir` | `deploy/dev/secrets/gateway` | Where the identity lives (`identity.json`, 0600, in a 0700 directory). |
   | `control.timeout` | `2s` | Control-plane call timeout. |
   | `broker.key_file`, `broker.kek_files` | — | Together. The first KEK file is current; the others are for KEK rotation. |
   | `egress.allowed_prefixes` | — | Private ranges this gateway may reach (operator only, HR-077). |
   | `approvals.approver_keys_file` | — | The reviewed approver keys file (§7). Without it, every approved action is refused. |
3. **Enroll**, with the token in a file readable only by you:
   ```bash
   pantherclaw-gateway enroll --config gateway.json --token-file enroll.token
   # enrolled gateway <id> of org <org>; certificate valid until <time>; identity in <dir>
   ```
   The gateway generates its Ed25519 key, sends the token with a certificate request it signed, and checks the CA against the pin.

   For development, `pantherclaw-server dev seed --gateway-out FILE` (or `dev gateway --org ID --out FILE`) writes an enrollment file instead. `pantherclaw-gateway serve --enroll-file FILE` uses that file only when there is no usable identity or the certificate expired.
4. **Serve**:
   ```bash
   pantherclaw-gateway serve --config gateway.json
   ```
   The gateway listens only after it has:
   - the first containment snapshot;
   - its configuration;
   - its broker key registered (when it has one).

   It waits up to 30 seconds for these. It refuses every dispatch while its containment stream is more than 2 seconds old (`containment_stale`).

## 4. Renewal

- Certificates last 24 hours. The gateway renews at 16 hours, over mTLS, with a new key. A failed renewal is retried every minute until expiry.
- The replaced certificate stays valid for 10 minutes, so calls in flight finish.
- If a renewal is missed, the certificate expires and `serve` stops with `gateway.certificate_expired`. Enroll again with a new token (§2–§3).

## 5. Check a gateway

```bash
pclaw gateway list [--include-revoked]
pclaw gateway get <gateway-id>    # the gateway, its 20 newest certificates (serial, key thumbprint, state, validity), its broker keys (version, fingerprint, active)
```

## 6. Revoke

```bash
pclaw gateway revoke <gateway-id> --reason "host decommissioned"   # every certificate, at once
pclaw gateway revoke-cert <gateway-id> <certificate-id>             # one replica's certificate
```

Revoking a gateway does all of this in one transaction:
- raises the containment epoch, so outstanding permits fail `BeginDispatch`;
- revokes the gateway and every certificate;
- writes `gateway.revoked` to the ledger.

The server checks the certificate's row on every call, caching it for at most a second, so the gateway is refused within about a second. Its own stream also tells it `gateway_revoked`. Connections on a revoked gateway stop until they are moved to another gateway (a weakening change, notified to org admins).

If the host or its identity directory may be compromised, also treat the broker key as compromised ([key-rotation.md](key-rotation.md) §5) and follow [incident-response.md](incident-response.md).

## 7. Approver keys (HR-038)

A gateway checks every approval itself, so an approval forged in PantherClaw's database is never dispatched (T-030). The permit of an approved action carries the approval's binding, the canonical input it hashes, and the WebAuthn assertion of every approver who counted ([PAP-1](../protocol/PAP-1.md) §7.2). Before `BeginDispatch`, the gateway checks:

- that the binding is the SHA-256 of its input, and that the input names the requested action and the action the permit binds;
- for each assertion:
  - a `webauthn.get` whose challenge is the binding, or the hash of a batch that contains it;
  - the relying party's SHA-256 in the authenticator data;
  - the user-presence and user-verification flags;
  - a signature that verifies with a key in the approver keys file;
- that no person or key counts twice, and that each requirement has as many people as it asks for.

Any failure refuses the action as `enforcement_failed` / `approval_unverified`, and nothing is committed or sent. A gateway with no file, a file that does not load, or a file without the signer's key refuses every approved action (fail closed). Actions that needed no approval are not affected. The refused permit expires unused, so the server restores its approval (HR-011): once the file is fixed, the agent's resubmission is dispatched.

**Export and review** (a person holding `gateway.read`):

```bash
pclaw approver-keys export --out approver-keys.json
# Approver keys of org <org> for relying party <rp id>: 2 key(s)
#   "bob@example.com (Bob)"  key "Desk key"  ES256  sha256:4f1c…
```

The command writes the active security keys of the org's enabled people, with the WebAuthn relying party and the org. Everyone with a key is listed, because a step-up is made by the run's launcher or principal, who need not be an Approver. The server still decides who counts; the gateway only refuses an assertion that no pinned key signed.

Check the list before installing it:
- every person on it may approve or step up for this org;
- no key is missing for an approver;
- the fingerprints match the ones you exported last time, apart from the keys you expect to have changed.

A person or key that should not be there is an incident: [incident-response.md](incident-response.md).

**Install:** copy the file to the gateway host, where only the operator can change it, and set `approvals.approver_keys_file`. The gateway reads the file again whenever its size or modification time changes, so no restart is needed. At start it logs `gateway.approver_keys` (keys and relying party) or `gateway.approver_keys_unavailable`.

**Refresh the file** whenever someone adds, removes or replaces a key, and when an Approver joins or leaves. Until you do:
- a new key's approvals are refused at the gateway;
- a removed key's approvals are refused by the server, which checks eligibility again at use (HR-170).

**Format** (`pantherclaw.approver-keys/v1`, JSON):
- `org`, `rp_id` and `exported_at`;
- `keys`, each with:
  - `user` (the person's id);
  - `label` and `key_name` (for review only);
  - `credential_id` (base64url);
  - `algorithm` (COSE: -7 ES256, -8 EdDSA, -257 RS256);
  - `public_key` (base64 DER SubjectPublicKeyInfo);
  - `fingerprint` (`sha256:` and the hex SHA-256 of the DER).

The gateway refuses a file for another org, with unknown members, or with a fingerprint, algorithm or key that do not match. For development, `dev seed --gateway-out FILE` writes `approver-keys.json` next to the enrollment file, and `deploy/dev/gateway.example.json` pins it.
