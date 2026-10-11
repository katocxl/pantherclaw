<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw Go SDK (Apache-2.0)

`github.com/katocxl/pantherclaw/sdk/go` is the Go client of the PantherClaw Authority Protocol, PAP/1 ([docs/protocol/PAP-1.md](../../docs/protocol/PAP-1.md)). It is its own module and uses only the Go standard library.

| Package | What it does |
|---|---|
| `pap` | Wire constants. The workload key file (`ReadKeyFile`, `WriteKeyFile`, `Thumbprint`). RFC 8785 canonical JSON (`Canonical`). Strict ActionIR parsing with the action hash (`ParseAction`, `ActionHash`), so an SDK can check the action a gateway decided. Request proofs (`SignProof`), and PantherClaw's proof checks (`CheckProof`), for fake gateways in tests and for services that verify PAP/1 themselves. Workload token claims read without verifying (`ParseTokenClaims`): when to renew, and which key a token is bound to. |
| `client` | The workload client. A proof over every request, with one retry for a fresh nonce (`use_nonce`). Workload tokens renewed at the server (`WorkloadService.IssueToken`), with one retry for an expired one. `Authorize`: an agent's raw tool call through the gateway's `/sdk/{connection}` face, read by `Evaluate` with the action id, the label and the hash checked. `Wait` long-polls a held call (`WorkloadService.Wait`), `Stream` follows the SSE wait stream (`GET /v1/wait/{handle}`), and `AuthorizeAndWait` waits and then resubmits the identical call with the same action id once it is ready (PAP/1 §8). It fails closed (HR-200): unreachable, timed out, an error, or an answer it cannot read or check is `CannotDecide`, never `Allow`. |

Target verifier middleware follows in a later M8 pull request.

Every package is tested against the shared vectors in [`sdk/conformance`](../conformance), which PantherClaw generates from its own implementation. `PANTHERCLAW_CONFORMANCE_DIR` points the tests at another copy. Run them with `task sdk:check`, or with `go -C sdk/go test ./...`.
