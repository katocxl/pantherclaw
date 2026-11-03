# Runbook — `pclaw siem forward`

**Milestone:** M27 follow-up (founder decision FD8, D660; F950, HR-662, T-284). **Audience:** SOC teams. **Edition:** Business, as the [SIEM export](siem-export.md) it receives.

`pclaw siem forward` receives PantherClaw's SIEM export, verifies each batch and appends each of its OCSF events as one line to a file, or writes it to stdout. A SIEM agent that reads files then takes the events in: Sentinel's Azure Monitor Agent as a custom text log, Wazuh's `localfile` as JSON. It is how the [Sentinel](../../integrations/siem/sentinel/README.md) and [Wazuh](../../integrations/siem/wazuh/README.md) packs get one event per line.

It needs no PantherClaw login. It posts to no SIEM and adds no token or key. It checks no edition.

## 1. Before you start

1. Create a SIEM export destination ([siem-export.md](siem-export.md)) and keep its signing secret (`whsec_…`), shown once.
2. Optional: opt the destination in to Ed25519 signatures (`SetSIEMDestinationSignatureScheme`, `hmac+ed25519`). The answer names the org's webhook JWKS URL, `https://<pantherclaw>/.well-known/pantherclaw/orgs/<org>/webhook-jwks.json`.
3. Pick the host: the one the SIEM agent runs on. The export posts only over HTTPS, on port 443 or 1024 to 65535:
   - A private or loopback address makes the destination internal, which a person confirms with a security key. Use the address itself (`https://10.0.0.5:8471/`), not `localhost`, which a destination URL refuses, and a certificate that names it.
   - Hosted PantherClaw can reach only a public address.

## 2. Start it

```
pclaw siem forward --listen 10.0.0.5:8471 --tls-cert forwarder.crt --tls-key forwarder.key \
  --secret-file /etc/pantherclaw/siem.secret \
  --jwks-url https://pc.example.com/.well-known/pantherclaw/orgs/<org>/webhook-jwks.json \
  --out /var/log/pantherclaw/ocsf.json
```

| Flag | Meaning |
|---|---|
| `--out PATH` or `--out -` | Required. The file the events are appended to. If it is missing, it is created for the forwarder's user only (§4). An existing file keeps its permissions and content. `-` writes to stdout, and the log stays on stderr |
| `--listen ADDR` | Default `127.0.0.1:8471`. Plain HTTP is served on loopback only. Any other address, `0.0.0.0` and `:8471` included, needs `--tls-cert` and `--tls-key` |
| `--tls-cert`, `--tls-key` | PEM certificate and key. TLS 1.3 only |
| `--secret-file PATH` | The destination's secret, as shown. At most two: give both during a rotation. Or set `PCLAW_SIEM_SECRET` to one secret, not both. A secret is never taken as an argument |
| `--jwks-url URL` or `--jwks-file PATH` | The org's webhook JWKS, to check the Ed25519 `v1a,` signature. The URL is https, fetched at start and refetched at most once a minute when a signature matches no key it holds (the signature names no key) |
| `--window DURATION` | Default `5m`, at most `15m`: how far a batch's timestamp may be from this host's clock, either way |

It refuses to start without an HMAC secret or a JWKS. Run it under your service manager. It stops on an interrupt or on SIGTERM, a service manager's stop (on Windows also a console close, logoff or shutdown). Then it takes no new connection and gives the batches in flight up to 30 seconds to finish.

## 3. What it checks

In this order, before anything is written:

1. The Standard Webhooks headers `webhook-id`, `webhook-timestamp` and `webhook-signature` are present and well formed.
2. The body is at most the export's largest batch, 1 MiB, and arrives within 10 seconds.
3. The bodies in hand, read but not yet written or refused, hold at most 32 MiB in all. Their bytes are counted as they arrive and given back when the request is answered. A read that would pass 32 MiB is answered 503 `busy` before any signature is checked. A sender that stalls holds only the bytes it sent, for at most 10 seconds, so idle connections can't keep a batch out. The exporter sends one batch at a time per destination and retries a 503.
4. The timestamp is within the window of this host's clock, and not before the forwarder started.
5. Every configured scheme has a valid signature over `webhook-id.webhook-timestamp.body`: an HMAC-SHA256 `v1,` by one of the secrets (constant-time compare), and with a JWKS an Ed25519 `v1a,` by one of its webhooks keys. One scheme alone is not enough when both are configured.
6. The `webhook-id` was not already written in the window. A copy, or the exporter's re-send with a newer timestamp, is answered 200 and not written again.
7. The body is an export batch (`pantherclaw.ocsf.batch`) whose events are JSON objects.

| Answer | When |
|---|---|
| 200 `ok` | Written and synced |
| 200 `duplicate` | Already written in the window; nothing written |
| 400 | Headers or batch malformed, the body not received within 10 seconds, or the timestamp outside the window or before the start |
| 401 | A configured scheme has no valid signature |
| 413 | Over 1 MiB |
| 503 `busy` | The bodies in hand already hold 32 MiB. Nothing is written, and the exporter retries |
| 503 `write failed` | A write that failed part way is cut back to the last whole batch, and the exporter's retry is written. A sync that failed after a whole write keeps the lines, because agents tailing the file would read it again from the start if it were cut back. The forwarder then writes nothing more: every later batch gets 503 until it is restarted. With `--out -`, a write that took part of a batch stops it the same way, because a stream can't be cut back |

An answer never echoes the request. Each batch that reaches the forwarder logs one JSON line on stderr with the batch id, the event count when known and the outcome, never the body. A body whose declared length is over 1 MiB never reaches it: the server answers 413 before the forwarder logs anything. A chunked body over 1 MiB is logged as `too_large`. A refused write also logs the system's error, such as a full disk.

## 4. The output

- One OCSF event per line, compact JSON, exactly as the exporter mapped it: the layout of `integrations/siem/samples/`.
- A file is synced before the 200. Nothing is written for a refused batch.
- The forwarder seeks to the end before each batch, so `logrotate` with `copytruncate` works. It does not reopen a renamed file. On Windows an open file can't be renamed or deleted at all, so rotate it by restarting the forwarder or by copy-truncate.
- When it opens an existing file that does not end in a newline, it adds one first. A missing newline means the forwarder was killed, or the power lost, in the middle of a write. The fragment then stays a line of its own and never takes the next event with it. The SIEM may reject that one line. Its batch was never answered 200, so the exporter sends it again.
- The file holds what the rules will trust: keep it writable only by the forwarder's user, and readable by the agent. A file the forwarder creates is that user's alone:
  - On Linux and macOS it has mode 0600.
  - On Windows, which ignores the mode, it gets a protected access list that allows only that user, SYSTEM and Administrators. Nothing is inherited from the folder, whose entries often let every local user change what it holds.
- An existing file keeps its permissions: its mode, or on Windows its access list. If the agent runs as another user, create the file beforehand with the group, mode or access list the agent needs, and check that no one else can write to it.
- Delivery is at least once. After a restart, or once a batch's window has passed, a re-sent batch is written again. Dedupe on `metadata.uid`.

## 5. Rotations and restarts

- **Secret rotation:** for 24 hours the export signs with both secrets. Start the forwarder with both `--secret-file`s before or as you rotate, and with the new one only after the overlap.
- **Ed25519 key rotation:** with `--jwks-url` the new key is fetched on the first batch it signs (at most once a minute). With `--jwks-file`, save the new JWKS and restart: the retiring key stays in the JWKS for 24 hours.
- **Restart:** stop it with SIGTERM or an interrupt, so the batches in flight finish (§2). The ids written before are forgotten, so a batch signed before the start is refused (400) and goes through on the exporter's retry with a new timestamp. Timestamps are whole seconds, so this can include a batch signed in the second the forwarder started.
- **Clock ahead, then a restart:** if the exporter's clock runs ahead of this host's (by at most the window), a batch signed shortly before a restart can carry a timestamp after the start. A copy of it that arrives after the restart is then written again. That is a duplicate of a batch PantherClaw signed, never a forgery. Dedupe on `metadata.uid`.
- **Clock skew:** keep both clocks synced. A host more than the window off refuses every batch as outside the window.

## 6. When delivery fails

The destination's health ([siem-export.md](siem-export.md) §3) shows the forwarder's answers: `http_401` (wrong or missing secret, or no Ed25519 signature while a JWKS is configured), `http_400` (clock or a start just now), `http_503` (disk, or `busy`). Fix the cause. After a failed sync, or a partial write to stdout, restart the forwarder once the disk is fixed. The exporter retries and the cursor never skips.

## 7. What was not checked

- Tested offline: each check above, the CLI's refusals, and the real exporter's batch posted over TLS to the forwarder, written as the mapper's lines and not again on a re-send. Also tested: the drain on stop, the newline added on open, and the new file's mode (Linux and macOS) or access list (Windows).
- SIGTERM is tested by sending it on Linux and macOS. On Windows only the list of stop signals is checked.
- No Azure Monitor Agent or Wazuh agent has read a file it wrote.
