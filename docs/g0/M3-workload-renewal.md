### G0 — M3 follow-up: workload token renewal for long-running services — 2026-10-10

This brief is written before implementation (G0). It plans the M3 follow-up "`pclaw workload` renewal daemon for long-running services" ([G0 M3](M3.md), follow-ups).

**Purpose:** a workload token is valid for 10 minutes (PAP-1 §3.4). Today a long-running service has to call `pclaw workload token` in a loop of its own, or issue tokens itself; only `pclaw mcp proxy` keeps its token fresh. This follow-up adds one supported way: `pclaw workload renew` keeps a valid token in place for as long as the service runs, and stops with a clear message when the server refuses renewal.

**Scope:**
- `internal/identity/workloadclient`: a `Renewer` (renewal schedule, backoff, refusals) and the token hand-over of decision 1. `pclaw mcp proxy` moves onto the same `Renewer`, so the refresh logic exists once.
- `pclaw workload renew --key-file FILE --out FILE [--github | --kubernetes-token FILE] [--declared-release sha256:…]`, which runs in the foreground until it is stopped.
- The workload-identity runbook (a systemd unit, a Kubernetes sidecar, Windows) and BUILD_GUIDE §4.
- No server, protocol, migration or proto change (decision 3).

**Out of scope:** SDKs for other languages (M8); signing requests on the service's behalf (a local signer would let any local process act as the workload); hardware-backed keys.

**Threat slice:** T-032 (a token without its key is useless, and the hand-over never carries the key), T-033 (no listener), T-041 (tokens never in logs), T-046 (attestation tokens stay single use when re-attesting).

**Hardening rules in scope:** HR-056 (the token never appears in logs, arguments or the environment), HR-090 (each renewal is a fresh key-only proof), HR-092 (no listener, by analogy with desktop workloads), HR-143 (re-attestation only with fresh attestation tokens; the server keeps a token from outliving its attestation).

**Design:**
1. **Schedule.** The renewer asks for a new token once half of the current token's lifetime has passed, minus up to 10% jitter so that a fleet started together spreads out. That is about 5 minutes for a 10-minute token, and sooner for an L2 token that its attestation cuts short (HR-143). The lifetime is measured on the local clock, from receipt to the response's `expire_time`, and capped at 10 minutes, so a server clock that runs ahead never delays renewal.
2. **Failures.** A transient failure is retried after 1 s, doubling up to 30 s, with jitter: network errors, timeouts, `Unavailable`, `use_nonce` after the transport's own retry, `proof_replay`, `rate_limited`, and `invalid_proof`. A proof fails to verify when the key file's server URL is not the server's `public_url`, but also when this machine's clock is more than a minute off, which NTP may correct. The current token stays in place until a new one arrives. Each failure prints one line on stderr that says when the current token expires, or that it has expired.
3. **Refusals.** These codes end renewal, because retrying cannot help:
   - `instance_not_admitted`: the instance was revoked, rejected or never admitted, or its agent is suspended or retired;
   - `key_mismatch`: the key file does not hold the instance's key;
   - `invalid_token`: the server does not know the instance.

   Each code gets its own message with the cause and the next step (for example `pclaw instance get ID` for the owner). The command then exits with code 3, which a supervisor can be told not to restart (systemd `RestartPreventExitStatus=3`).
4. **Re-attestation.** With `--github`, every renewal sends a fresh Actions OIDC token. With `--kubernetes-token`, the renewer sends an attestation only after the kubelet has rotated the projected token (its SHA-256 changed), because each attestation token is single use (HR-143). When the server refuses an attestation, the renewer reports it and asks again at once without one. The server refuses a reused attestation token as `invalid_token`, so on a request that carries an attestation, that code means the attestation, not the instance. This matters because the projected token a pod enrolled with has already been used. The server then issues L2 tokens until the last attestation expires, and L1 tokens after that (its existing behaviour). Every level change is reported.
5. **Shutdown.** SIGINT or SIGTERM (Ctrl-C, or stopping the service on Windows) stops the renewer between requests, and the command exits 0.
6. **Logs** carry the instance id, the level and the expiry, never the token (HR-056).

**Founder decisions** (asked in the Claude Code session on 2026-10-10; each answered with the recommended option):
1. **How the token reaches the service.** The token is sender-constrained (`cnf.jkt`): to use it, the service also needs the key file. The service already holds that key, under the same owner-only protection.
   - **(a) Recommended: an owner-only file, replaced atomically.** Each new token is written to a new file created with mode 0600 in the target's directory, flushed, and renamed over `--out`. A reader sees the old token or the new one, never part of one. The renewer never writes through a symlink and never truncates a file in place. On Windows the file inherits the directory's ACL, like the key file. The runbook says to put both files in a directory only the service's user can write (`/run/<service>`, or a memory-backed `emptyDir` shared with the sidecar). There is no listener and nothing new to configure. The service reads the file whenever it builds a request.
   - **(b) An exec wrapper:** `pclaw workload run … -- service args`. The same file, but in a fresh private temporary directory: its path reaches the child in `PANTHERCLAW_WORKLOAD_TOKEN_FILE`, and the directory is removed when the child exits. Renewal lives exactly as long as the service, and there is no well-known path. In exchange, pclaw becomes the service's parent: two supervisors, signal forwarding, and weak signal semantics on Windows. It could come later, on top of (a).
   - **(c) A local socket** that serves the current token: a Unix socket at mode 0600 in a 0700 directory with a peer-UID check, or a named pipe on Windows. No token is ever at rest. But it is a listener that any process of that user can ask, which HR-092 forbids for desktop workloads for the same reason. Every service also needs a client for it, and Windows has no equivalent peer check. Not recommended.

   *Answer:* (a), an owner-only file replaced atomically.
2. **What happens to the token file.**
   - **(a) Recommended:** on a refusal (design 3) the renewer removes the file, so the service stops presenting an identity the server has refused. On a normal stop it leaves the file in place: the token expires within 10 minutes by itself, and a restarted renewer replaces it, so restarting the renewer does not interrupt the service.
   - **(b)** Always leave it; the gateway refuses the token anyway.
   - **(c)** Always remove it, even on a normal stop.

   *Answer:* (a). A refusal removes the file and exits with code 3; a normal stop leaves it in place.
3. **The kill switch and renewal.** `IssueToken` does not look at the kill switch today. The kill switch stops actions at `Authorize`, at `BeginDispatch` and in the gateways; identity keeps working, so restoring brings back exactly what was there (kill-switch runbook). There is also no instance quarantine: suspending the agent is the closest thing, and it already refuses renewal with `instance_not_admitted`.
   - **(a) Recommended:** keep it that way. Renewal continues while the kill switch is engaged, and the service sees `kill_switch` from the gateway on every action. No server change.
   - **(b)** `IssueToken` refuses while the kill switch is engaged. That needs a new PAP-1 error code (or reuses `instance_not_admitted`, which would mislead), a server change, and an integration test. Every service would lose its token within 10 minutes and come back on its own after the restore.

   *Answer:* (a). Renewal continues while the kill switch is engaged; no server change.

**Tests to write first:**
- `Renewer` with a fake clock: the schedule (half the lifetime, the jitter bound, a short L2 lifetime, the 10-minute cap when the server clock runs ahead); backoff that doubles and caps, while the current token stays in place; each refusal code ends renewal with its own message, and transient codes do not; shutdown between requests.
- The hand-over: the file is replaced atomically, created 0600, never written through a symlink; refusal and shutdown leave it as decision 2 says.
- `pclaw workload renew` against a fake `WorkloadService`: Kubernetes re-attestation only after rotation, and a refused attestation followed by a retry without it; GitHub re-attestation on every renewal; exit code 3 on a refusal; the token never on stdout or stderr. `pclaw mcp proxy` keeps its HR-092 tests on the shared `Renewer`.
- Integration (`internal/identity/adapters/workloadrpc`, real server and database, a fake clock shared by server and client): one renewer keeps a valid token in the file across five token lifetimes, checked at every 30 s step; revoking the instance and suspending the agent then each end it with `instance_not_admitted`.

---

### Status — 2026-10-10

**Delivered** in #148 (322e4a6), as designed, with the three founder decisions as answered:
- `workloadclient.Renewer` (`internal/identity/workloadclient/renewer.go`) and the atomic token file (`tokenfile.go`); `pclaw mcp proxy` now renews through the same `Renewer`.
- `pclaw workload renew --key-file FILE --out FILE [--github | --kubernetes-token FILE] [--declared-release sha256:…]` (`internal/pclaw/workload_renew.go`). A refusal removes the file and exits with code 3.
- The workload-identity runbook ("Long-running services": a systemd unit and a Kubernetes sidecar) and BUILD_GUIDE §4.
- No server, protocol, migration or proto change.

**Tests:** `TestRenewerRenewsHalfwayThroughEachToken`, `TestRenewerFollowsTheTokensLifetime`, `TestRenewerBacksOffAndKeepsTheCurrentToken`, `TestRenewerStopsAtARefusal`, `TestRenewerShutsDownCleanly`, `TestTokenFileIsReplacedAtomically` (workloadclient); `TestWorkloadRenewKeepsTheTokenFileFresh`, `TestWorkloadRenewReattestsKubernetesOnlyAfterRotation`, `TestWorkloadRenewReattestsWithGitHubEveryTime`, `TestWorkloadRenewStopsCleanly` (pclaw); and the integration test `TestIntRenewerKeepsAValidTokenAcrossExpiries` (workloadrpc).
