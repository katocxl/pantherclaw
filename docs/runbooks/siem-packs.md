# Runbook — SIEM content packs

**Milestone:** M27 ([G0 M27](../g0/M27.md) D509, D536, D539, D551). **Audience:** SOC teams. **Edition:** Business, as the [SIEM export](siem-export.md).

`integrations/siem/` holds six packs: Splunk, Sentinel, Chronicle, Elastic, Wazuh and Sigma, under Apache-2.0. Each holds the same eight single-event rules, `pc-siem-001` to `pc-siem-008`, listed in `rules.yaml`, on the OCSF 1.9 export. The packs are data: no scripts and no third-party content.

## What the rules do

- Searches and rules ship disabled where the vendor has that state. Wazuh has none: its rules go live on load, raise alerts and start no active response.
- No rule fires on a simulated event (`test` in `metadata.labels`).
- Every rule reads one event. Rates and thresholds are yours to set.
- Sentinel has no critical severity, so `pc-siem-006` is High there.
- `pc-siem-007` lists its event codes: created, activated, state_changed, secret_rotated and signature_scheme_set. A routine retry (`siem.destination_retried`) is not one of them.

## Getting events in

The export posts signed Standard Webhooks batches: `{"type": "pantherclaw.ocsf.batch", "data": {"events": [...]}}`. Each pack README has an Ingest section.

| SIEM | How the batch is split |
|---|---|
| Splunk | Sourcetype `pantherclaw:ocsf:batch` on HEC raw splits it (LINE_BREAKER, SEDCMD, the envelope to the null queue), renamed to `pantherclaw:ocsf` |
| Elastic | A Logstash `split` pipeline; an ingest pipeline can't split |
| Chronicle | The parser loops over `data.events` |
| Sentinel | Can't split: a DCR returns one row per record. `dcr.json` takes one event per record, and the Logs Ingestion API also needs an Entra token |
| Wazuh | Can't split: a decoder reads one line as one event. It needs one OCSF event per line |
| Sigma | States the field layout the rules expect |

**Sentinel and Wazuh need the batch split first.** `pclaw siem forward` ([siem-forwarder.md](siem-forwarder.md)) does it: it writes one event per line to a file that the Azure Monitor Agent or the Wazuh agent reads.

- The signature is not verified inside any SIEM. Nothing there refuses an old timestamp or dedupes `metadata.uid`.
- Several SIEMs want a token or key the export doesn't send: HEC, the Chronicle feed, Sentinel.
- `pclaw siem forward` checks the signature, the timestamp and re-sends before it writes. It writes to a file only and adds no token. Without it, keep ingest endpoints reachable only from PantherClaw or a checking proxy.

## What is and isn't proven

- Tested offline: the golden samples are byte for byte the mapper's output, and each rule, read from the vendor's own file by a small parser, fires on exactly the samples `rules.yaml` lists.
- Against `samples/batch/batch.json`, the Splunk split and the Logstash split both return the samples. The Sentinel DCR covers every OCSF key, and Wazuh fires nothing on an unsplit batch. The Chronicle loop is shape-checked only.
- No vendor engine ran any rule. Each pack's README has a "What was not checked" section.
- Chronicle is the least proven: its parser has never run and its rules have never been compiled.
- No pack has a certification, a store listing or a vendor review.

## Acting on exported alerts

- An alert's basis is in `unmapped.pantherclaw_uncertainty`. An inference is a reason to look, not proof.
- PantherClaw's automations contain only on CONFIRMED alerts (OBSERVED or RULE_MATCH).
- **A customer's own SOAR or script acting on exported alerts is outside PantherClaw's control.** The refusal does not reach it: read the basis before acting.
