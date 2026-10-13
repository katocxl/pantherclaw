<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw SDK conformance vectors

These JSON files define the bytes that every PantherClaw SDK (Go, TypeScript, Python) must produce or accept. They are generated from PantherClaw's own Go implementation, which is what the gateway and the Authority run. An SDK that passes them computes the same canonical JSON, hashes, proofs and key files as PantherClaw does.

The vectors are generated, never edited by hand. The generator lives in the main repository at `internal/conformance/gen` and reads the real implementation (`internal/actionir`, `internal/identity/workloadclient`, `internal/approvals/domain`, `internal/identity/pap` and `internal/authority/finalize`; action tokens are also run through the payments simulator's verifier). It also runs as a drift test in `task check`: if the implementation changes and the vectors do not, the test fails. To rewrite them after an intended change, run `task sdk:vectors` and review the diff.

Every SDK runs every vector. A vector an SDK cannot run is a failure, never a skip (G0 M8). The normative protocol is [PAP-1](../../docs/protocol/PAP-1.md); these files are examples of it, not a replacement.

## File format

Every file is one JSON object:

| Member | Meaning |
|---|---|
| `format` | `pantherclaw.conformance/v1` |
| `group` | the file's group name (below) |
| `description` | what the group checks, in one paragraph |
| `source` | the Go code the vectors came from |
| `cases` | the vectors |

Runners ignore members they do not know. Hashes are lowercase hex where the name says `sha256` or `hash`, and base64url without padding elsewhere (`bh`, `ath`, `jkt`, `binding`, `seed`, JWK `x`). Times are Unix seconds.

## Groups

| File | What a runner checks |
|---|---|
| `jcs.json` | RFC 8785 canonicalization. For each case with `canonical`, canonicalize `input` and compare bytes and `sha256`. For each case with `reject`, canonicalization must fail: lone surrogates, duplicate member names (also after unescaping), invalid UTF-8 (`input_hex` holds those bytes), anything that is not exactly one JSON value, nesting deeper than PantherClaw's limit of 10000. An SDK may refuse shallower nesting than that; no accepted vector nests deeper than 16. Numbers follow ECMAScript `Number.prototype.toString` (so `-0` → `0`, `1e21` → `1e+21`, integers beyond 2^53 → the nearest double), and members sort by UTF-16 code units. |
| `actionir.json` | ActionIR v1 (PAP-1 §6). For each accepted case, `input` has every object's members reversed and whitespace added: parse it strictly, canonicalize it and compare with `canonical`; `action_hash` is the hex SHA-256 of `canonical`. Every case with `reject` must be refused by the SDK's strict ActionIR parser; `reject` names the rule (HR-100: strict JSON, unknown members, depth and size, and `v` written exactly `1`; HR-101: no JSON numbers in parameters; HR-102: identifiers are printable ASCII, so no confusables or bidi controls; HR-103: nothing missing or ambiguous). An optional member written `null` is accepted and kept in the canonical form, as PantherClaw parses it. `input_hex` holds input that is not valid UTF-8. SDKs never send ActionIR: they parse the action the gateway returns, to check it and its hash (HR-201). |
| `approval_bindings.json` | Approval bindings (PAP-1 §8). Canonicalize `input` and compare with `canonical`; `binding` is base64url SHA-256 of `canonical`. |
| `key_files.json` | The workload key file. Read each accepted `file`, derive the Ed25519 public key (`public_x`) and its RFC 7638 thumbprint (`jkt`). A writer must produce `file` byte for byte: members `private_key`, `identifier`, `server`, `run_id` in that order, each omitted when empty, no whitespace, a final newline. Every rejected `file` must fail to load. |
| `workload_tokens.json` | Workload tokens as the Authority issues them (PAP-1 §3.4). SDKs read them without verifying: decode `claims`, check that `cnf.jkt` is the `jkt` of `workload_key`, and compute `ath` = base64url SHA-256 of the token; `exp` says when to renew. Every case with `reject` must be refused: not a compact JWS, `pap.v` other than 1, an audience other than `pantherclaw-gateway`, no `exp`, no `cnf.jkt`. A runner may also verify signatures with the key in `jwks` whose kid starts with `workload-tokens-`. |
| `proofs.json` | PAP-Proof JWS (PAP-1 §4). For each of `proofs`, an SDK builds exactly `header` and `claims` (members in the order shown, no whitespace) and the compact `proof` from `key.seed`, `method`, `url`, `body`, `token`, `nonce`, `iat` and `jti`; Ed25519 is deterministic, so the bytes must match. For each of `htus`, the SDK's htu for `url` must be exactly `htu`, or the SDK must refuse to sign when `reject` is set: the URL without query and fragment, the scheme in lower case, the host as written (case and port kept), and the path as Go's `url.URL.EscapedPath` gives it (kept as written when every character is allowed there and every escape is valid, otherwise decoded and re-escaped with upper-case hex; dot segments are kept). For each of `checks`, the SDK's proof checker, given `proof`, the request (`method`, `url`, `body`, `token`) and the clock `now`, must answer `answer`: `ok` or the PAP-Error code (`invalid_proof`, `key_mismatch`, `body_hash_mismatch`, `use_nonce`), checking in the order of PAP-1 §4. htu matches when its scheme and host are equal without case and its escaped path is exactly the request's. `iat` may be at most 60 seconds ahead and 6 minutes behind, both inclusive. PantherClaw signs and accepts proofs with `alg` `EdDSA` only: design decision 3 widens verifiers to `Ed25519`, and this vector follows when the server's proof check does. The token in every check is valid; only its `cnf.jkt` matters there. |
| `action_tokens.json` | Target-side verification of action tokens (PAP-1 §10, HR-202), for target verifier middleware and verification functions. For each case, present `token` (empty: no `PAP-Action` header) with exactly `body`, for the route's `operation`, `target_type` and `target_id`, to a verifier configured with `jwks`, `issuer`, `audience`, a clock at `now` and, when `store` is `unavailable`, a replay store that cannot record. It must answer `expect`: `ok` or the refusal code (`missing`, `bad_signature`, `wrong_issuer`, `wrong_audience`, `expired`, `body_mismatch`, `operation_mismatch`, `replayed`, `store_unavailable`). For `twice`, the first presentation is `ok` and the second gives `expect`. For `then_valid`, the same verifier and store then accept the minted token's case (the first case: its token, body, operation and target): a refusal never spends its `jti`, even one a forged token carries. Only keys whose kid is `action-tokens-` and the first 22 characters of their RFC 7638 thumbprint verify; `alg` is `EdDSA` or `Ed25519`; a token is accepted while the clock is before `exp` plus 5 seconds and `iat` is at most 5 seconds ahead, with a lifetime of at most 60 seconds (as the payments simulator's verifier checks); `typ` is `pap-action+jwt`, `pap.v` is 1 and `aud` is a single string, or the answer is `bad_signature`; spend `jti` only after every other check passed. A connection test's test tokens (HR-188's one exception: `pap.txn` the connection test, `pap.op` its package's `test: true` read, `pap.target` the connection itself, `bh` an empty body) are checked like any other, so the strict operation and target match keeps one to the bodiless read it binds: another operation, target or body is refused, and so is the test's second token, bound to another body. |

## Fixed keys

Every key in the vectors is derived from a public name, so none of them is secret: the Ed25519 seed is `SHA-256("pantherclaw conformance " + name)`. The names are `workload` (the agent's key), `another workload` (a key that is not the token's), `workload_tokens`, `action_tokens` and `receipts` (the Authority's keys in `jwks`), and `another deployment` (an action-tokens key that no JWKS publishes). The fixed identifiers are those of the ActionIR goldens: org `01920000-0000-7000-8000-000000000001`, environment `…002`, run `…003`, action `…004`, instance `…005`, agent `…006`, connection `…007` and, in `action_tokens.json`, the connection test `…00a` of the test tokens. Never use these keys outside tests.

## Runners

Each SDK runs these files in its own test suite:

- Go: `sdk/go`;
- TypeScript: `sdk/typescript`;
- Python: `sdk/python`.

`task sdk:check` runs all three (it is not part of `task check`).
