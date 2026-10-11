<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw Go SDK (Apache-2.0)

`github.com/katocxl/pantherclaw/sdk/go` is the Go client of the PantherClaw Authority Protocol, PAP/1 ([docs/protocol/PAP-1.md](../../docs/protocol/PAP-1.md)). It is its own module and uses only the Go standard library.

| Package | What it does |
|---|---|
| `pap` | Wire constants. The workload key file (`ReadKeyFile`, `WriteKeyFile`, `Thumbprint`). RFC 8785 canonical JSON (`Canonical`). Strict ActionIR parsing with the action hash (`ParseAction`, `ActionHash`), so an SDK can check the action a gateway decided. Request proofs (`SignProof`), and PantherClaw's proof checks (`CheckProof`), for fake gateways in tests and for services that verify PAP/1 themselves. Workload token claims read without verifying (`ParseTokenClaims`): when to renew, and which key a token is bound to. |

The client (nonce retry, token renewal, the gateway's `/sdk` face, waits on held calls) and target verifier middleware follow in later M8 pull requests.

Every package is tested against the shared vectors in [`sdk/conformance`](../conformance), which PantherClaw generates from its own implementation. `PANTHERCLAW_CONFORMANCE_DIR` points the tests at another copy. Run them with `task sdk:check`, or with `go -C sdk/go test ./...`.
