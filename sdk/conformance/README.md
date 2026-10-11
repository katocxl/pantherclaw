<!-- SPDX-License-Identifier: Apache-2.0 -->
<!-- Copyright 2026 Joshua Kato -->

# PantherClaw SDK conformance vectors

These JSON files define the bytes that every PantherClaw SDK (Go, TypeScript, Python) must produce or accept. They are generated from PantherClaw's own Go implementation, which is what the gateway and the Authority run. An SDK that passes them computes the same canonical JSON, hashes, proofs and key files as PantherClaw does.

The vectors are generated, never edited by hand. The generator lives in the main repository at `test/conformance` and reads the real implementation (`internal/actionir`, `internal/identity/workloadclient`, `internal/approvals/domain` and, for the tokens, `internal/identity/pap` and `internal/authority/finalize`). It also runs as a drift test in `task check`: if the implementation changes and the vectors do not, the test fails. To rewrite them after an intended change:

```bash
go test ./test/conformance -run TestConformanceVectors -update
```

Then review the diff. The normative protocol is [PAP-1](../../docs/protocol/PAP-1.md); these files are examples of it, not a replacement.

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
| `jcs.json` | RFC 8785 canonicalization. For each case with `canonical`, canonicalize `input` and compare bytes and `sha256`. For each case with `reject`, canonicalization must fail: lone surrogates, duplicate member names (also after unescaping), invalid UTF-8 (`input_hex` holds those bytes), anything that is not exactly one JSON value. Numbers follow ECMAScript `Number.prototype.toString` (so `-0` → `0`, `1e21` → `1e+21`, integers beyond 2^53 → the nearest double), and members sort by UTF-16 code units. |
| `actionir.json` | ActionIR v1 (PAP-1 §6). `input` has every object's members reversed and whitespace added. Canonicalize it and compare with `canonical`; `action_hash` is the hex SHA-256 of `canonical`. A case whose `reject.level` is `jcs` must be refused by any canonicalizer. A case at level `actionir` is refused only by the strict ActionIR parser (unknown members, JSON numbers in params, nesting, identifiers), which SDKs need not implement; an SDK's canonicalizer may accept it. SDKs never send ActionIR: they use the canonicalizer only to check the hash the gateway returns (HR-201). |
| `approval_bindings.json` | Approval bindings (PAP-1 §8). Canonicalize `input` and compare with `canonical`; `binding` is base64url SHA-256 of `canonical`. |
| `key_files.json` | The workload key file. Read each accepted `file`, derive the Ed25519 public key (`public_x`) and its RFC 7638 thumbprint (`jkt`). A writer must produce `file` byte for byte: members `private_key`, `identifier`, `server`, `run_id` in that order, each omitted when empty, no whitespace, a final newline. Every rejected `file` must fail to load. |

## Fixed keys

Every key in the vectors is derived from a public name, so none of them is secret: the Ed25519 seed is `SHA-256("pantherclaw conformance " + name)`. The name `workload` is the agent's key. The fixed identifiers are those of the ActionIR goldens: org `01920000-0000-7000-8000-000000000001`, environment `…002`, run `…003`, action `…004`, instance `…005`, agent `…006` and connection `…007`. Never use these keys outside tests.

## Runners

Each SDK runs these files in its own test suite:

- Go: `sdk/go`;
- TypeScript: `sdk/typescript`;
- Python: `sdk/python`.

`task sdk:test` runs all three.
