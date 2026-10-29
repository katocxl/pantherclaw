# ADR-0041 — The hosted gateway pool: one gateway process per organization on shared hosts

**Status:** Accepted (2026-10-29). Founder decision G9 was answered with the recommended option. The [G0 M19 brief](../g0/M19.md) records it with the coordinator's design decision D203. Builds on [ADR-0002](0002-control-plane-and-gateway-split.md) (the gateway is a separate process with no database) and the M9 connector isolation (HR-084, HR-085, HR-216).

**Context.** A gateway certificate binds exactly one organization and one gateway in its URI SAN (`pc:org/<org>/gateway/<gateway>/cert/<cert>`), and everything the server does for a gateway takes the organization from that certificate (HR-181). PantherClaw-hosted gateways exist today only as a static list in the server's configuration (`gateways.pantherclaw_hosted`). They run no connector containers (HR-084), and nothing provisions, isolates, routes or retires them.

Hosted multi-tenant gateways (PN-010.4) need a way to run many organizations' gateways on shared infrastructure without changing what a gateway certificate means. A single multi-org gateway process would need a new trust model. It would hold many organizations' credentials and broker keys in one address space, and the server would have to trust the gateway for the organization instead of the certificate.

**Decision.**
1. **One gateway process per organization** (G9; HR-499). A hosted gateway is an ordinary gateway, enrolled like any other, whose certificate names that one organization. Shared hosts run many such processes, never one process for many organizations.
2. **Records, not configuration.**
   - Operator-level `pc.hosting_hosts` (no `org_id`, read through the audited cross-org lister) lists the hosts.
   - `pc.hosted_gateways` (with `org_id` and RLS) records each organization's hosted gateway: host, state, gateway and resources.
   - The configuration list stays as a fallback for one release.
3. **Provisioning by a worker job and a host agent.**
   - The provisioner creates the gateway record and a single-use enrolment token.
   - The host agent `pantherclaw-host` pulls the token over its own mTLS identity. That identity is a host certificate kind with purpose `hosting` and no organization, and it can never call organization RPCs (HR-500).
   - The agent hands the token to the gateway process only through a file on the process's private tmpfs, never in an environment variable, an argument or a log (HR-502).
4. **Isolation per organization** (HR-501).
   - Each process runs in its own container: a non-root uid, a read-only root, all capabilities dropped, no Docker socket, cgroup CPU, memory and pids limits, and its own network namespace.
   - It is started through the Docker CLI with fixed arguments, as connector containers are (HR-216).
   - Hosted gateways run no connector containers (HR-084 unchanged).
5. **Routing keeps mTLS end to end.** Each organization gets a hostname `<slug>.gw.<domain>`. The host forwards by SNI without terminating TLS, so agents and the server still meet the gateway's own certificate.
6. **Lifecycle.**
   - Team plan and above, one hosted gateway per organization, with a plan quota.
   - Upgrades roll one organization at a time, with a health check, toward the target version of M18's fleet policy.
   - Deprovisioning revokes the certificate (epoch bump) before the process is stopped (HR-503).

**Consequences.**
- "Certificate = organization identity" stays true for hosted gateways. No server code trusts a gateway for its organization, and HR-181 needs no exception.
- A compromise of one organization's process exposes only that organization. The host agent is the shared component, and it holds no organization authority and never sees an organization's credentials beyond the single-use token it passes on.
- Each organization costs one process (a gateway RSS target of < 150 MB, PN-011.1). Capacity grows with hosts, not with a denser process.
- Cross-tenant breakout (T-216), a hijacked host agent or token (T-217) and noisy neighbours (T-218) are the new threats. The isolation profile, the agent's identity and the cgroup limits answer them.
- Third-party MCP servers on hosted gateways remain out (HR-084). A per-org process makes a later decision possible, but this ADR does not take it.
- Building and releasing `pantherclaw-host` needs a `.github` change, which the founder makes.

**Alternatives.**
- One shared multi-org gateway process: a new trust model, with many organizations' keys in one process. Rejected by G9.
- A port per organization instead of SNI: works, but leaks an organization count and complicates firewalls.
- Terminating TLS at a shared proxy: breaks end-to-end mTLS.
- systemd units with per-uid sandboxing: possible on one host, weaker than a container profile already proven for connectors.
- Kubernetes namespaces per organization: a later deployment option, not needed at $0.
- Founders pasting enrolment tokens by hand: does not scale, and puts tokens in chat or shell history.
