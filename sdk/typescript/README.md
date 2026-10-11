<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw TypeScript SDK (Apache-2.0)

`@pantherclaw/sdk` is the TypeScript client of the PantherClaw Authority Protocol, PAP/1 ([docs/protocol/PAP-1.md](../../docs/protocol/PAP-1.md)). It has **no runtime dependencies**: Ed25519 comes from WebCrypto, SHA-256 from `node:crypto`, and RFC 8785 canonical JSON from its own strict parser. It needs Node 22.18 or later.

**The npm name is not reserved yet.** The founder still has to create the npm organization `@pantherclaw` and set up trusted publishing ([BUILD_GUIDE](../../docs/BUILD_GUIDE.md) Day-0 item 4). Until then the package is `private`, and no build or publish step exists. The sources are TypeScript that Node runs directly (type stripping), so the package uses only erasable syntax. A `tsc` build to JavaScript and declarations comes with the release pipeline.

| Module | What it does |
|---|---|
| `jcs.ts` | `parseJSON` (strict: duplicate members, lone surrogates and invalid UTF-8 are refused), `serialize` and `canonicalize` (RFC 8785: members sorted by UTF-16 code units, numbers as ECMAScript writes them). |
| `action.ts` | `parseAction`: ActionIR v1 with the structural checks PantherClaw makes (HR-100..103, `actionir.json`), with its canonical form and hex action hash. An SDK uses it to check the action a gateway decided; it never builds or sends one (HR-201). |
| `pap.ts` | The workload key file (`parseKeyFile`, `readKeyFile`, `writeKeyFile` without overwriting, `marshalKeyFile` byte for byte; a key file it hands back never prints or stringifies its seed (a literal, spread copy or structured clone of one loses that); on Windows the 0600 mode is not enforced, so keep the file in a directory only its owner can read), Ed25519 workload keys from WebCrypto (`WorkloadKey.fromSeed`, `thumbprint`), request proofs (`signProof`, byte for byte as PantherClaw signs them, with the htu PantherClaw's Go client signs: `htu`, `splitURL`), and workload token claims read without verifying (`parseTokenClaims`). |
| `check.ts` | `checkProof`: PantherClaw's proof checks of PAP/1 §4 steps 2–5, returning `ok` or the PAP-Error code, for fake gateways in tests and services that verify PAP/1 themselves. |
| `client.ts` | `Client`, the workload client. It signs a proof over every request, with one retry for a fresh nonce, and renews workload tokens at the server, with one retry for an expired one. `authorize` sends an agent's raw tool call through the gateway's `/sdk/{connection}` face: an MCP tool with its server, or a configured built-in (`builtins`); any other name is never sent (`classify`). `evaluate` reads the answer strictly: an allow or a hold must carry the canonical sdk-channel action (`action_ir`) under the action id sent, hashing to its hash; an observe answer lets only a built-in run; on a target-enforced connection the result's `send` is the gateway's request (`outboundRequest`), sent unchanged. `hook` asks the local connection's `/hook` face about a shell command, as Claude Code's hook does. `wait` long-polls, `stream` follows the SSE wait stream, and `authorizeAndWait` and `resume` wait, at most until the hold's deadline, and resubmit the identical call, at most three times. Server and gateway URLs must use https (http only on loopback); redirects are refused. It fails closed (HR-200): anything PantherClaw cannot decide is `cannot_decide`, never `allow`. |

A target-side action-token verifier follows in a later M8 pull request.

## Tests

`node --test "test/**/*.test.ts"` (or `task sdk:check` from the repository root) runs every module against the shared vectors in [`sdk/conformance`](../conformance), which PantherClaw generates from its own implementation. `PANTHERCLAW_CONFORMANCE_DIR` points the tests at another copy.
