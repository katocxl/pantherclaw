# Runbook — Anchoring the global root

**Milestone:** M7 · **Owner:** the platform operator · **Edition:** Team and above · **Status:** the job, its failure states and the offline verification are tested against local fakes and recorded Sigstore responses; the first live run against Sigstore's public services is made only with the founder's agreement (it publishes an entry) and recorded in the M7 exit status.

Every org's evidence ledger has signed checkpoints ([evidence-verification.md](evidence-verification.md)). Anchoring adds an outside witness: every `evidence.anchoring.interval` the worker builds one Merkle tree over a blinded leaf per org, signs the root with the `anchors` key, enters it in a Rekor v2 transparency log and has an RFC 3161 authority timestamp it. A rewritten history then conflicts with a root that the log and the authority hold. Background: [g0/M7.md](../g0/M7.md) design decision 12; HR-195; PAP-1 §9.4.

## What is published, and what is not

Each anchor enters one entry in the configured log, **publicly**: a `hashedrekord` v0.0.2 with the SHA-256 of the anchor statement, the `anchors` key's ECDSA P-256 signature and its public key. The statement holds the deployment's `evidence.log_origin`, the period, the number of leaves and the global root. It names no org.

Each org's leaf is `SHA-256(0x00 ‖ "pantherclaw.anchor-leaf.v1" ‖ nonce ‖ SHA-256(checkpoint note))` with a fresh 32-byte nonce per org per anchor, and the leaves are ordered by their own value. Without an org's nonce nobody can tell which leaf is whose or whether the org was active: a quiet org's leaf changes every anchor. The nonce stays in the org's own `anchor_leaves` row; the global `anchors` table holds only the leaves and the root.

The number of leaves tells the log how many orgs with a checkpoint the deployment had at that time.

## Turn it on

1. **Licence.** On a Community licence the server refuses to start with anchoring on (`evidence.anchoring needs a Team licence or higher`).
2. **Choose the log and the authority.** Nothing is hard-coded. Sigstore's public services are the defaults in [`deploy/dev/server.example.json`](../../deploy/dev/server.example.json): the Rekor v2 log `https://log2025-1.rekor.sigstore.dev` and the timestamp authority `https://timestamp.sigstore.dev/api/v1/timestamp`. Sigstore shards Rekor v2 by year and retires old shards, so check the current values before each change:
   - take Sigstore's current `trusted_root.json` and signing configuration from its TUF repository (<https://github.com/sigstore/root-signing>, `targets/`), and verify them as Sigstore documents (for example with `cosign trusted-root` or a TUF client);
   - the log entry (`tlogs[]` of a Rekor v2 log) gives the base URL and the public key (`publicKey.rawBytes`, PKIX DER, base64): write it as a PEM `PUBLIC KEY` file;
   - the timestamp authority (`timestampAuthorities[]`) gives the certificate chain (`certChain.certificates[].rawBytes`): write them as one PEM file, the signing certificate first and the root last.
   Any other Rekor v2 log and RFC 3161 authority work the same way (a private Rekor deployment, a commercial authority).
3. **Configure** (file or environment):

   ```json
   "evidence": {
     "anchoring": {
       "enabled": true,
       "interval": "1h",
       "rekor": { "url": "https://log2025-1.rekor.sigstore.dev", "public_key_file": "/etc/pantherclaw/rekor.pub", "origin": "log2025-1.rekor.sigstore.dev" },
       "tsa": { "url": "https://timestamp.sigstore.dev/api/v1/timestamp", "cert_chain_file": "/etc/pantherclaw/tsa-chain.pem" }
     }
   }
   ```

   `interval` is 5 minutes to 24 hours (default 1 hour). `rekor.origin` is the origin the log's checkpoints carry; empty means the URL without its scheme, which is Rekor v2's convention. Environment: `PC_EVIDENCE_ANCHORING_ENABLED`, `PC_EVIDENCE_ANCHORING_INTERVAL`, `PC_EVIDENCE_REKOR_URL`, `PC_EVIDENCE_REKOR_PUBLIC_KEY_FILE`, `PC_EVIDENCE_REKOR_ORIGIN`, `PC_EVIDENCE_TSA_URL`, `PC_EVIDENCE_TSA_CERT_CHAIN_FILE`.
4. **Network.** The worker reaches only those two hosts, over https, through the egress client (no redirects, no proxy, no private or loopback addresses: HR-070..072). Allow them in your firewall.
5. **Restart the worker.** It refuses to start when a file is missing or malformed.

### Keys from Sigstore's TUF repository (G0 M35 D1040)

Instead of key and chain files, the worker can take the log's key and the authority's chain from Sigstore's `trusted_root.json`, fetched through TUF:

```json
"evidence": {
  "anchoring": {
    "enabled": true,
    "trust": "tuf",
    "tuf": { "cache_dir": "/var/lib/pantherclaw/tuf" },
    "rekor": { "url": "https://log2025-1.rekor.sigstore.dev" },
    "tsa": { "url": "https://timestamp.sigstore.dev/api/v1/timestamp" }
  }
}
```

- The TUF client starts from the Sigstore root that ships in the binary (`internal/evidence/sigstoretuf/root.json`, Sigstore's root v14 as published in `sigstore-go` v1.3.0), walks the root rotations the repository publishes, and accepts `trusted_root.json` only when the TUF metadata verifies. `tuf.repository` defaults to `https://tuf-repo-cdn.sigstore.dev`; `tuf.cache_dir` keeps the verified metadata between refreshes (empty: nothing is cached). Environment: `PC_EVIDENCE_ANCHORING_TRUST`, `PC_EVIDENCE_TUF_REPOSITORY`, `PC_EVIDENCE_TUF_CACHE_DIR`.
- The worker picks, from the trusted root, the Rekor v2 log whose checkpoint origin is `rekor.origin` (or the URL without its scheme) and the timestamp authority whose URI is `tsa.url`. The URLs stay configuration: the log shard is not discovered from Sigstore's signing configuration.
- A daily job (`evidence.tuf_refresh`) refreshes the material, and the anchoring tick refreshes it when it is older than a day. Until a refresh succeeds the worker creates anchors but submits none. A failed refresh writes `evidence.tuf_refresh_failed` to the platform audit ledger and keeps the last verified material; nothing falls back to unverified keys.
- The worker reaches the TUF repository through the egress client, like the log and the authority: allow `tuf-repo-cdn.sigstore.dev` (or your repository's host) in the firewall.

## Root log and witnesses (G0 M35 D1041)

Every anchored global root is also appended to one append-only log for the whole deployment, the root log, with the origin `<evidence.log_origin>/global`. Its leaves are the anchors' global roots in the order they were anchored; its tiles and checkpoints are in `pc.global_log_*` and `pc.global_checkpoints`, signed with the deployment's `global_log` Ed25519 key (published in `evidence-keys.json`). Each append first re-checks the previous checkpoint and proves the new tree consistent with it; a mismatch writes `evidence.global_log_failed` and signs nothing.

The newest checkpoint, with the witnesses' cosignatures appended, is public at `GET /.well-known/pantherclaw/evidence/global-checkpoint` (text, a C2SP signed note). `?consistency=<old size>` returns JSON with the checkpoint and the consistency proof from that size. It shows the root log's size and root only: no org, no per-org checkpoint.

**Witnesses** (Business edition and above; needs anchoring) cosign root log checkpoints over the C2SP tlog-witness protocol:

```json
"evidence": {
  "witnesses": [
    { "name": "witness.example.org", "url": "https://witness.example.org", "vkey": "witness.example.org+1a2b3c4d+BASE64KEY" }
  ],
  "witness_threshold": 1
}
```

- `url` is the witness's https prefix (the request goes to `<url>/add-checkpoint`); `vkey` is the witness's cosignature/v1 verifier key as it publishes it. At most 16 witnesses; `witness_threshold` 0 means every one.
- Every 5 minutes the worker sends the newest root log checkpoint to each witness with the consistency proof from the size that witness last cosigned, keeps each verified cosignature in `pc.global_checkpoint_cosignatures`, and retries once at the size a witness answers with a conflict. Only the root log is ever sent to a witness, never an org's checkpoint.
- Sending a checkpoint to a public witness publishes it there. Make the first live run only with the founder's agreement.
- A witness that refuses, times out or returns a cosignature that does not verify writes `evidence.witness_failed` (witness name and code); fewer verified cosignatures than the threshold writes `evidence.witness_threshold_not_met`. The checkpoint stays published either way.

## How it runs

The worker ticks every minute. A tick:

1. creates the current period's anchor if there is none (one per period; a second worker inserts nothing): it lists the active orgs through the audited cross-org lister (purpose `orgs`, at most 10,000 orgs), reads each org's latest checkpoint in its own tenant transaction, and stores the anchor as `PENDING` with each org's leaf, nonce and checkpoint;
2. for at most 4 anchors that are `PENDING`, or `FAILED` with attempts left and their backoff over: enters the statement in the log and checks the answer (the entry is the one rebuilt from the anchor, the inclusion proof leads to the log's checkpoint, the checkpoint is signed by the configured key with the configured origin), keeps the verified entry, then asks the authority for a timestamp over the statement's signature (SHA-256, with a nonce) and checks the token against the configured chain. Only with both verified is the anchor `ANCHORED`.

No database transaction is open while the worker talks to the log or the authority, and authorization reads nothing anchoring writes: a slow, failing or unreachable log never delays or changes a decision (design decision 20).

## Failures

A failed attempt leaves the anchor `FAILED` with an error code, writes `evidence.anchor_failed` to the platform audit ledger (anchor id, code, attempt, period) and logs it (ids and codes only; responses are never logged). It is retried after 1, 2, 4, 8, 16 and then 30 minutes, at most 8 attempts; the next period's anchor covers every org again anyway. A verified log entry is kept, so a retry after a timestamp failure does not enter the statement again.

| Code | Meaning | What to do |
|---|---|---|
| `REKOR_FAILED` | The log could not be reached, timed out or refused the entry. | Check the URL, the firewall and the log's status page. |
| `REKOR_INVALID` | The log's answer does not verify: another entry, an inclusion proof that does not lead to its checkpoint, or a checkpoint not signed by the configured key or not of the configured origin. | The log key or origin changed (Sigstore rotated or retired the shard): update them from the current trusted root. If they did not change, treat it as a possible attack on the log path and follow [incident-response.md](incident-response.md). |
| `TIMESTAMP_FAILED` | The authority could not be reached or timed out. | Check the URL and the firewall. |
| `TIMESTAMP_INVALID` | The authority refused, or its token does not verify against the configured chain, covers other data, answers another nonce or predates the period. | Update the chain from the current trusted root, or check the clock of the worker host. |
| `KEY_UNAVAILABLE` | The `anchors` key that signed the statement was revoked before the anchor was logged. | Nothing: the next period's anchor uses the new key. |

Check the state as `pc_audit_ro`:

```sql
SELECT period, state, attempts, error_code, next_at, anchored_at FROM pc.anchors ORDER BY period DESC LIMIT 24;
```

An org sees its anchors with `EvidenceService.ListAnchors` (permission `evidence.read`): the anchor's state, the org's leaf position and checkpoint, the global root.

## Verify

`pclaw evidence bundle` includes the org's newest anchored leaf: the nonce, the anchor's leaves, the signed statement, the Rekor entry and the timestamp, with the anchored checkpoint and the consistency proof from it to the latest one. `pclaw verify --sigstore-trusted-root trusted_root.json` checks offline that the org's leaf for that checkpoint is in the anchor, that the leaves build the statement's root, the statement's signature by a pinned `anchors` key, the Rekor entry against the logs of the trusted root you supply, and the timestamp against its authorities. Without a trusted root the log and timestamp checks are reported as not available; a bundle of an org not anchored yet reports the anchor as not available.

## Changing the log or the authority

Change the configuration and restart the worker. Anchors already `ANCHORED` keep verifying against a trusted root that lists the old log and authority (Sigstore keeps retired logs in `trusted_root.json` with their validity). Anchors still `PENDING` or `FAILED` are entered in the new log at their next attempt.

## Key rotation

The `anchors` key rotates like the other signing keys ([key-rotation.md](key-rotation.md)). A retiring key keeps its published validity, so anchors it signed keep verifying; new anchors use the new key. Pin the new key with `pclaw evidence trust` before relying on bundles signed after the rotation.
