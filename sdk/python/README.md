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

The `/sdk` client with waits and a target-side action-token verifier follow in later M8 pull requests.

## Tests

From `sdk/python`, run `PYTHONPATH=src python -m unittest discover -s tests` (or `task sdk:check` from the repository root). The tests run every module against the shared vectors in [`sdk/conformance`](../conformance), which PantherClaw generates from its own implementation. `PANTHERCLAW_CONFORMANCE_DIR` points them at another copy.
