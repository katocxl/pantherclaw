# ADR-0001 — Go for all backend binaries

**Status:** Accepted (2026-10-08)

**Context.** The inherited architecture proposed TypeScript/NestJS. PantherClaw is a security-critical enforcement product that must install effortlessly, sit on the hot path of agent actions, and minimize supply-chain risk. The founder works on Windows and has no budget.

**Decision.** Server, gateway, CLI, admin tool and simulators are written in Go (toolchain pinned in go.mod; go1.27.3 since 2026-10-21, EX-006; go1.27.2 from 2026-10-09, EX-003). SDKs are written in each agent ecosystem's language (Python, TypeScript, Go).

**Consequences.** Single static binaries (easy install, distroless images); stdlib crypto incl. HPKE X-Wing, ML-KEM, ML-DSA and a FIPS 140-3 mode; strong concurrency; small dependency trees with checksum-DB verification and reachability-aware `govulncheck`. The later UI will be TypeScript consuming generated Connect clients.

**Alternatives.** TypeScript/NestJS (heavier runtime, npm supply-chain surface, OPA as a sidecar); Rust gateway + Go server (two backend languages, slower MVP).
