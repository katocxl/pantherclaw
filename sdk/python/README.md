<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw Python SDK (Apache-2.0)

`pantherclaw` is the Python client of the PantherClaw Authority Protocol, PAP/1 ([docs/protocol/PAP-1.md](../../docs/protocol/PAP-1.md)). It needs Python 3.11 or later and uses standard-library HTTP. Its only dependency, for Ed25519, is `cryptography`. RFC 8785 canonical JSON comes from its own strict code.

**The PyPI name is not reserved yet.** The founder still has to create the pending trusted publisher `pantherclaw` on PyPI ([BUILD_GUIDE](../../docs/BUILD_GUIDE.md) Day-0 item 4). Until then nothing is published.

| Module | What it does |
|---|---|
| `pantherclaw.jcs` | `parse` (strict: duplicate members, lone surrogates, invalid UTF-8 and non-finite numbers are refused), `serialize` and `canonicalize` (RFC 8785: members sorted by UTF-16 code units, numbers as ECMAScript writes them). |
| `pantherclaw.action` | `parse_action`: ActionIR v1 checked as strictly as PantherClaw checks it (HR-100..103), with its canonical form and hex action hash. An SDK uses it to check the action a gateway decided; it never builds or sends one (HR-201). |
| `pantherclaw.pap` | The workload key file (`KeyFile.parse`, `read`, `write` owner-only without overwriting, `marshal` byte for byte), Ed25519 workload keys (`WorkloadKey`, `thumbprint`), request proofs (`sign_proof`, byte for byte as PantherClaw signs them), and workload token claims read without verifying (`parse_token_claims`). |
| `pantherclaw.check` | `check_proof`: PantherClaw's proof checks of PAP/1 §4 steps 2–5, returning `ok` or the PAP-Error code, for fake gateways in tests and services that verify PAP/1 themselves. |
| `pantherclaw.client` | `Client`, the workload client. It signs a proof over every request, with one retry for a fresh nonce, and renews workload tokens at the server, with one retry for an expired one. `authorize` sends an agent's raw tool call through the gateway's `/sdk/{connection}` face, and `evaluate` reads the answer, checking the action id, the PARTIAL label and the hash. `wait` long-polls, `stream` follows the SSE wait stream, and `authorize_and_wait` and `resume` wait and resubmit the identical call. It fails closed (HR-200): anything PantherClaw cannot decide is `cannot_decide`, never `allow`. |
| `pantherclaw.verifier` | `Verifier`: target-side verification of PantherClaw action tokens (PAP/1 §10, HR-202). It checks the JWS against an action-tokens key from the JWKS (alg `EdDSA` or `Ed25519`; cached 15 minutes; an unknown kid refetched at most once a minute), then `iss`, `aud`, the lifetime (at most 60 s, 5 s of skew), `pap.v`, the body hash, and operation and target through your `match`. Only then does it spend `jti` once in a `ReplayStore`. A failure raises a `Refusal` with its code and HTTP status. `MemoryStore` serves one replica (`single_replica`). A target with more replicas implements `ReplayStore` over a shared database. |

## Tests

From `sdk/python`, run `PYTHONPATH=src python -m unittest discover -s tests` (or `task sdk:check` from the repository root). The tests run every module against the shared vectors in [`sdk/conformance`](../conformance), which PantherClaw generates from its own implementation. `PANTHERCLAW_CONFORMANCE_DIR` points them at another copy.
