# Runbook — Key rotation

**Status:** broker keys, sealed credentials and the internal gateway CA are tested procedures (M6). The publication of the evidence keys with their validity and revocation is tested (M7, §7); their rotation, like the other rows, is an outline for the milestones named.

| Key | Rotation | Procedure | In code today |
|---|---|---|---|
| Authority signing keys (receipts, permits, workload tokens, action tokens) | 90 days, ≥ 7-day overlap | new key published in JWKS as `next` → promote to `active` → old key `verify-only` for 7 days → retire; the ledger records each step | Key-store support only; no operator command yet |
| Evidence signing keys (M7): `checkpoints` (Ed25519, signed checkpoints), `anchors` (ECDSA P-256, the anchored global root), `evidence_packs` (Ed25519, pack manifests), `checkpoints_pq` (ML-DSA-65, optional co-signatures, created only with `evidence.mldsa_cosign`) | 90 days, ≥ 7-day overlap, like the Authority keys | as the Authority keys, and §7 | Key-store support and publication (`evidence-keys.json`, `revoked-keys.json`); no operator command yet |
| Envelope DEKs (per org/purpose; M7 adds `evaluation_inputs`, the sealed replay inputs, and `payload_captures`) | yearly or on suspicion | create a new DEK version; new writes use it; a River job re-encrypts rows in batches; destroy the old version after verification | outline; sealed rows name their DEK version, so old rows stay readable while their version exists |
| KEK (key-encryption key files) | provider policy / on suspicion | rewrap all DEKs with the new KEK; verify decryption of samples; disable the old KEK | `pantherclaw-server keys gen-kek`; the gateway's `broker.kek_files` accepts old and new (§5) |
| Gateway broker keys | on suspicion, or when a gateway host is replaced | §5 | yes (M6) |
| Sealed connection credentials | at the provider's rotation, or on suspicion | §5.3 | yes (M6) |
| Internal gateway CA | on compromise, or planned with every gateway operator | §6: a new key, then every gateway re-enrolls | yes (M6): `pantherclaw-server keys rotate-gateway-ca`; without downtime in M13 |
| Offline roots (licence, package) | only on compromise | freeze promotions, publish revocation, re-sign with a new root, ship the root update in a signed release | procedure only |

Compromise of any key: treat it as an incident ([incident-response.md](incident-response.md)), rotate immediately and record G4.

## 5. Gateway broker keys (M6)

A gateway's broker key (X-Wing) opens the credentials sealed to it. It is generated on the gateway host and never leaves it. The private key is stored encrypted with a KEK file. Background: [g0/M6.md](../g0/M6.md) design decision 8; HR-060, HR-061, HR-182.

### 5.1 Generate and register a new key (gateway operator)

```bash
pantherclaw-gateway broker-key generate --out /etc/pantherclaw/broker-2.json --kek-file /etc/pantherclaw/kek
# broker key sha256:… written to …; give this fingerprint to whoever seals credentials
```

1. Point `broker.key_file` at the new file and restart the gateway.
2. At start the gateway registers the key over its mTLS identity, retrying until it succeeds; it serves nothing before.
3. The server records it as the next version and retires the previous one. A retired key can never be registered again (`BROKER_KEY_REUSED`).
4. Check with `pclaw gateway get <gateway-id>`: the new version is active, with the fingerprint printed by `generate`.

### 5.2 Re-seal every credential of the gateway's connections (credential owner)

Credentials sealed to the old key are still delivered to the gateway, but it can no longer open them. Calls through those connections fail with `enforcement_failed` / `credential_unavailable` until they are sealed again. So plan the restart and the re-sealing together:

```bash
pclaw credential list <connection-id>                              # versions, broker key, state
pclaw seal --connection <connection-id> --from-file secret.txt --fingerprint sha256:<new fingerprint>
```

`pclaw seal` asks for the active broker key of the connection's gateway, prints its fingerprint, and seals on your machine; the plaintext never leaves it. `--fingerprint` refuses to seal to any other key. If the key changes between the two steps, the upload is refused (`BROKER_KEY_CHANGED`): run `seal` again.

### 5.3 Rotate or revoke a credential

- **Rotate:** rotate at the provider, then `pclaw seal` the new value. The new version supersedes the old one.
- **Revoke:** `pclaw credential revoke <connection-id> <version>`. This raises the epoch, so outstanding permits fail. Replacing a credential is a weakening change and is notified to org admins.
- **KEK rotation for the broker key file:** a key file stays wrapped with the KEK it was generated with; nothing rewraps it. To retire a KEK:
  1. generate a new KEK (`pantherclaw-server keys gen-kek --out …`);
  2. generate a new broker key with it (§5.1);
  3. re-seal (§5.2);
  4. drop the old KEK from `broker.kek_files`.

## 6. Internal gateway CA

The internal CA (signing-key purpose `gateway_ca`) issues two things:
- the gateways' 24-hour client certificates;
- the gateway listener's server certificate.

The CA certificate is derived from the key, so its SHA-256 (`ca_sha256`) stays the same for the key's lifetime. Every gateway pins it at enrollment, and refuses a renewal that returns another CA.

Replacing the CA therefore means every gateway enrolls again. That is the M6 procedure (founder decision 2026-10-10). Rotation without downtime is planned for M13. Replace the CA when its key may be compromised, or on a planned schedule with every gateway's operator ready.

1. **Contain**, if the key may be compromised. Engage the kill switch when actions may have been authorized through a forged gateway ([kill-switch.md](kill-switch.md)), and follow [incident-response.md](incident-response.md).
2. **Replace the key** (server operator):
   ```bash
   pantherclaw-server keys rotate-gateway-ca --config server.json --confirm
   # replaced the gateway CA: new key …, pin sha256:… (was sha256:…); revoked 1 earlier key(s)
   ```
   One transaction creates the new key and revokes every earlier one, with no overlap. Without `--confirm` nothing changes.
3. **Restart every server instance**, so the listener presents a certificate from the new CA and trusts only it. From then on, every gateway is refused until it enrolls again: its pinned CA no longer matches.
4. **Re-enroll every gateway** ([gateway.md](gateway.md) §2–§3):
   - a gateway admin issues a new token with `pclaw gateway enroll-token`, which shows the new `ca_sha256`;
   - the operator sets `control.ca_sha256` to it and runs `pantherclaw-gateway enroll` again. A new identity replaces the old one in `identity_dir`.

   Broker keys and sealed credentials are unaffected: they belong to the gateway record, not to its certificate.
5. **Check:** `pclaw gateway get` shows a new certificate per gateway, and agent calls succeed again.

## 7. Evidence keys (M7)

Four platform signing keys sign evidence, besides the `receipts` key (G0 M7 design decision 17). The server creates `checkpoints`, `anchors` and `evidence_packs` when it starts, and `checkpoints_pq` only when `evidence.mldsa_cosign` is on. Each is wrapped by the KEK like every signing key.

| Purpose | Algorithm | Signs | Verified by |
|---|---|---|---|
| `checkpoints` | Ed25519 | each org's signed checkpoints (C2SP signed notes) | `pclaw verify` (`checkpoint.signature`, `witness.previous`) |
| `checkpoints_pq` | ML-DSA-65 | the optional co-signature of checkpoints and pack manifests | `pclaw verify` (`checkpoint.cosignature`, `pack.cosignature`), when the trust file pins it |
| `anchors` | ECDSA P-256 | the anchor statement over the global root, entered in the transparency log | `pclaw verify` (`anchor.signature`, `anchor.log`, `anchor.timestamp`) |
| `evidence_packs` | Ed25519 | evidence-pack manifests (`pap-pack+jwt`) | `pclaw verify` (`pack.signature`) |

**What verifiers rely on.** `/.well-known/pantherclaw/evidence-keys.json` lists every key of these purposes and of `receipts`, revoked ones included, with `not_before` (its creation), `not_after` (when it stopped signing; none while active) and its state. `/.well-known/pantherclaw/revoked-keys.json` lists the revoked ones. `pclaw evidence trust` pins the document once (trust on first use). `pclaw verify` accepts only pinned keys: a receipt's key must have been valid when the receipt was issued, an anchor's key when the timestamp was made, and a checkpoint's key must not be revoked (a signed note carries no time). So:

- **Keep a retired key published** for as long as evidence it signed is kept: removing it from the keystore makes every receipt, checkpoint, anchor or pack it signed fail for anyone who pins the document again.
- **After a rotation, users refresh their trust file.** A trust file pinned before the new key existed fails the new key's signatures (`signed by key … which is not in your trust file`). Tell them, and give them the new fingerprint through another channel than the deployment itself.
- **Anchors stay checkable.** An anchor names the `anchors` key that signed it, and the log entry carries its public key; a rotation changes neither.
- **On compromise**, revoke the key (it appears in `revoked-keys.json`) and treat it as an incident: a holder of the `checkpoints` key can re-sign a rewritten history, which only a checkpoint saved earlier (`pclaw verify --previous`) or an anchored root exposes ([evidence-verification.md](evidence-verification.md)).

Rotation has no operator command yet, as for the Authority keys (the table above). The per-org DEKs of `evaluation_inputs` (sealed replay inputs) and `payload_captures` follow the envelope DEK row: every sealed row names its DEK version, so rows sealed before a rotation stay readable while that version exists, and retention removes them on its own schedule ([retention.md](retention.md)).
