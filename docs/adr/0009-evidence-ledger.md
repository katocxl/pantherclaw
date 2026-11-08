# ADR-0009 — Evidence ledger: unchained writes, per-org chainer, Merkle checkpoints, Rekor

**Status:** Accepted (2026-10-08)

**Context.** Chaining receipts inside the authorization transaction would serialize all decisions of an org on one hot row, and Postgres sequences leave gaps on rollback.

**Decision.** Receipts and platform audit events are inserted **unchained** in their business transaction. A per-org chainer job (advisory lock) assigns sequence numbers and hashes to rows older than `pg_snapshot_xmin(pg_current_snapshot())`. Merkle tiles and Ed25519-signed checkpoints are produced per time window; one global root across all orgs is anchored to a Rekor v2 log with an RFC 3161 timestamp. The operator configures the log and the timestamp authority; their keys come either from configured files or, since M35 (D1040), from Sigstore's `trusted_root.json` fetched through TUF from an embedded root and refreshed daily. The log shard is not discovered from the TUF signing config. `pclaw verify` validates signatures, chain continuity and consistency proofs offline. Platform audit uses the same mechanism (one evidence system).

**Consequences.** Authorization throughput is not limited by chaining; integrity becomes provable after a short delay (seconds). Insider re-signing is detectable through external witnesses. The ledger proves integrity, not completeness.

**Operational note (M1 implementation, 2026-10-08).** `pg_snapshot_xmin` is cluster-wide: any open transaction in *any* database of the cluster holds back chaining for every org until it ends. PantherClaw bounds its own transactions (statement timeout 5 s, idle-in-transaction timeout 10 s), so chain latency stays in seconds when PantherClaw runs on a **dedicated PostgreSQL cluster**; sharing a cluster with long-running workloads delays (never corrupts) chaining. Entries remain unverifiable until chained, so `Verify` and evidence exports must report the unchained tail explicitly.
