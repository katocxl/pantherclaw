# ADR-0022 — Containment sandbox edge, per-session TLS interception and probe trust

**Status:** Proposed (2026-10-11; G0 M9 decisions 1, 2, 4, 5 and 8, answered by the founder with the recommended option; accepted with the [G0 M9 brief](../g0/M9.md))

**Context.** A coverage claim of `ENFORCED` must rest on evidence that every route other than PantherClaw is closed (§41 of the product specification, HR-121). Coding agents use ordinary tools: `curl`, `gh`, `git`, language HTTP clients and MCP servers. To give a raw API call the same action and decision as the MCP route (F099), PantherClaw must see that call as a request it can map, not as an opaque TLS stream. Docker gives the building blocks:
- internal networks;
- since Engine 28, a bridge `gateway_mode_ipv4=isolated` mode in which the host keeps no address on the network, so a container cannot reach the host either;
- per-container namespaces, capability dropping, `no-new-privileges` and seccomp;
- optionally the gVisor runtime.

Docker's embedded DNS resolver (127.0.0.11) still answers on user-defined networks; before Engine 26 it forwarded external queries from internal networks (CVE-2024-29018). The agent is untrusted (A1), and so is anything running in its container.

**Decision.**
1. **Topology** (decision 1). `pclaw sandbox run` creates, per session, one internal bridge network (`--internal`, `-o com.docker.network.bridge.gateway_mode_ipv4=isolated`, IPv6 off, no published ports). It attaches three containers to it:
   - the agent, attached to that network only;
   - the edge sidecar, also attached to a second, ordinary network to reach the gateway;
   - the probe container, attached to that network only.

   The agent's proxy variables (`HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY`, empty `NO_PROXY`) and CA variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `GIT_SSL_CAINFO`) point at the edge and at the session CA certificate. A tool that ignores them has no route at all, so it fails closed.
2. **The edge is the agent's only route** (HR-213, HR-214). The edge is a PantherClaw binary in an image pinned by digest. It listens only on the sandbox network as an HTTP proxy:
   - `CONNECT host:443` to a host that a mapped connection lists as an agent host is intercepted with a leaf certificate from the per-session CA.
   - Every other `CONNECT` (another host, another port such as 22, an IP literal) and every plain-HTTP request is refused with 403 and recorded.
   - Intercepted requests (HTTP/1.1, or HTTP/2 over ALPN) are forwarded to the gateway's HTTP face for that connection as PAP/1 requests, signed with the run's workload key that only the edge holds. The gateway maps them through the signed package and decides exactly as for any other face.
   - The edge drops the agent's `Authorization`, `Cookie` and `Proxy-*` headers before forwarding; the gateway re-serializes the request anyway (HR-075). A dropped credential is reported as a coverage finding (a found PAT).
3. **Per-session CA.** The edge generates the CA when it starts (ECDSA P-256), and its private key never leaves the edge's memory. The certificate:
   - is valid for at most the session's maximum length (24 hours);
   - has `pathLenConstraint: 0`;
   - carries X.509 name constraints that permit only the session's mapped agent hosts.

   The edge writes the certificate to a volume that the agent mounts read-only. Leaf certificates live at most one hour.
4. **Probes and their trust** (decision 2, HR-215). The agent's container, and everything it writes, is untrusted, so evidence never comes from it.
   - **Configuration checks** come from `pclaw` outside the sandbox: `docker info` and `docker inspect` of the network and containers (engine and API version, runtime, mounts, capabilities, user, read-only root, security options, networks).
   - **Network probes** run in a separate container on the agent's network.
   - **The external canary** is `pantherclaw-sim canary`, on the host by default. It listens for TCP, UDP, ICMP and DNS (an authoritative name per session) and records every hit that carries the session's marker.

   `pclaw` creates an Ed25519 key per session outside the sandbox and registers its public key with the server when it opens the session. The probe container and the canary get the private key through a read-only file mount that the agent cannot see. The server issues a single-use nonce. The probe report and the canary report are JWS over canonical JSON (`typ: pap-probe+jwt`) that bind the session, the nonce and the image digests. Unsigned, replayed or stale reports are rejected.
5. **Controls.**
   - **Positive controls must succeed**, or the run is inconclusive and promotes nothing:
     - the same probes, run on a deliberately open control network, reach the canary and the canary records them;
     - through the edge, a mapped route gets the gateway's decision.
   - **Negative controls must fail** (decision 2: a failed one blocks promotion):
     - inside the sandbox, every catalogue route is refused and the canary records nothing for the session;
     - an unmapped `CONNECT` is refused.

     A failed negative control also records a coverage finding and drops any current `ENFORCED` claim for the scope at once.
6. **Promotion expires** (decision 3, HR-211). Evidence that passes promotes the scope (agent × connection × operation, for the sandbox's instances) to `ENFORCED` for 24 hours by default. Any change to a connection, package, route, gateway, sandbox image or configuration, or credential drops it to `PARTIAL` at once. Reads after expiry return `PARTIAL` with the last valid record, whether or not a job has run.
7. **Hardening of every container** (HR-085, decision 4). Every container runs:
   - in its own namespaces, as a distinct non-root uid;
   - with a read-only root filesystem, `--cap-drop ALL` and `--security-opt no-new-privileges`;
   - under Docker's default seccomp profile;
   - with no host environment, no Docker socket and no host network.

   The probe container alone adds `NET_RAW` for ICMP probes. gVisor (`--runtime runsc`) is used when `docker info` lists it, and recorded either way; it is not required for `ENFORCED`, and on Docker Desktop it is detected and skipped (decision 8).
8. **The same machinery runs connectors** (decision 5). In a customer-hosted gateway, the gateway's host process starts each third-party MCP server in a hardened container on its own internal network with an edge, through the Docker CLI with fixed arguments. It never mounts the Docker socket (HR-084, HR-216). The connector holds placeholders, never credentials. Its egress goes through the edge to the gateway's egress path, which maps each request, decides it, and injects the sealed credential. That mediated egress is what lets such a route rise above HR-086's `PARTIAL` cap, given probe evidence.
9. **No new dependencies** (decision 8). The Docker CLI is called with fixed argument lists (never a shell and never user-supplied flags). Proxying, TLS, X.509 and JWS come from the standard library.

**Consequences.**
- A raw `curl` to `api.github.com` inside the sandbox becomes the same `github.pull.merge` action, with the same decision, as the MCP tool call (F099). A push with a found PAT or an SSH key has no route.
- The edge sees plaintext for mapped hosts. It is in the TCB for the routes it mediates, like the gateway (R-01). Clients that pin certificates fail closed.
- `git push` and fetch over HTTPS to `github.com` and over SSH are closed in M9: the agent changes repositories through mapped API operations. A mapping for git's smart-HTTP protocol is a follow-up.
- Sandbox evidence is only as trustworthy as the host and the person who runs `pclaw` (residual risk R-17). It names that person, is bound to a server nonce and expires within a day.
- Requires Docker Engine 28 or newer (HR-122, HR-218); older engines refuse to start a sandbox.

**Alternatives considered.**
- Transparent interception with iptables in the agent's network namespace: rejected. It needs `NET_ADMIN` in a container that shares the agent's namespace, which weakens isolation, and it breaks without a proxy-aware CA set-up anyway.
- An allowlist proxy without interception (`CONNECT` only to the gateway): rejected. A raw API call could not be mapped, so F099 would not hold, and the agent would need gateway-aware tools.
- Putting the gateway itself on the sandbox network: rejected. A shared gateway would hold every session's CA key and workload key, and one session could reach another.
- Probes inside the agent's container: rejected. The agent controls that container, so its results prove nothing.
