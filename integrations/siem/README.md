# PantherClaw SIEM content packs

Detection content for six SIEMs, built on the OCSF 1.9 events PantherClaw exports. It is data written by the PantherClaw project, with no scripts and no third-party content, licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)). The SIEM export itself is a Business feature: see [docs/runbooks/siem-export.md](../../docs/runbooks/siem-export.md).

| Pack | Format |
|---|---|
| [splunk](splunk/README.md) | App directory: saved searches, a macro, an event and a batch sourcetype |
| [sentinel](sentinel/README.md) | ARM template of scheduled analytics rules, table schema, data collection rule |
| [chronicle](chronicle/README.md) | YARA-L rules, a batch parser and the field map |
| [elastic](elastic/README.md) | Detection rule export, ingest pipeline, index template, Logstash batch pipeline |
| [wazuh](wazuh/README.md) | Rules file |
| [sigma](sigma/README.md) | Sigma rules |

These packs are not certified, listed or reviewed by any vendor, and there are no store packages.

## The rules

Each pack holds the same eight rules. [rules.yaml](rules.yaml) lists them and the samples each must fire on.

| Id | Rule | Severity |
|---|---|---|
| `pc-siem-001` | High or critical alert | high |
| `pc-siem-002` | Incident opened | high |
| `pc-siem-003` | Action denied | low |
| `pc-siem-004` | Enforcement coverage invalidated | medium |
| `pc-siem-005` | Containment action | medium |
| `pc-siem-006` | Kill switch engaged | critical |
| `pc-siem-007` | SIEM export changed | medium |
| `pc-siem-008` | Unclaimed agent discovered | low |

Each rule reads one event. Rates and thresholds depend on your traffic, so add them in your SIEM. Searches and rules ship disabled: turn on the ones you want.

Sentinel has no critical severity, so `pc-siem-006` is High there.

A simulated event carries the label `test` in `metadata.labels`, and no rule fires on one.

## Getting events in

PantherClaw posts batches to one HTTPS URL. Each POST is signed with Standard Webhooks and holds up to 100 events:

```json
{"type": "pantherclaw.ocsf.batch", "data": {"batch": "…", "from_seq": 1, "to_seq": 2, "events": [{"class_uid": 2004}]}}
```

The rules read one OCSF event at a time, with its field names unchanged. Each pack's README has an Ingest section that turns a batch into those events, where the SIEM can:

| Pack | Split |
|---|---|
| Splunk | `pantherclaw:ocsf:batch` sourcetype on HEC's raw endpoint |
| Elastic | Logstash pipeline (an ingest pipeline can't split) |
| Chronicle | The custom parser loops over `data.events` |
| Sentinel | Not possible: a data collection rule returns one row per record. `pclaw siem forward` splits the batch into a file that the Azure Monitor Agent reads |
| Wazuh | Not possible: a decoder reads one line into one event. `pclaw siem forward` splits the batch into the file the agent reads |
| Sigma | Not applicable: the README states the field layout the rules expect |

**The signature is not verified inside any SIEM.** None of them reads the Standard Webhooks headers. Anyone who can post to the ingest endpoint can therefore write events the rules will trust, and nothing refuses an old timestamp or drops a duplicate `metadata.uid`. Several SIEMs also want a token or key that the export doesn't send. `pclaw siem forward` ([runbook](../../docs/runbooks/siem-forwarder.md)) verifies the signature, refuses a timestamp outside its window and answers a re-sent batch without writing it again, then writes the events to a file; it adds no token and posts to no SIEM. Without it, keep each ingest endpoint reachable only from PantherClaw or from something you run that checks the signature.

## Acting on what these rules find

A PantherClaw alert states how it knows what it says, in `unmapped.pantherclaw_uncertainty`: for example `OBSERVED`, `RULE_MATCH` or `INFERRED`. An inference is a reason to look, not proof. PantherClaw's own automations refuse to contain on an inferred alert. A SOAR or script of yours that acts on these exported events is outside PantherClaw's control, and that refusal doesn't reach it: read the field before you act.

## How the packs are tested

[samples/](samples/) holds golden OCSF events, byte for byte what the exporter writes for those fixtures. Some are events a rule must fire on, and others are near misses it must not: a low alert, a closed incident, a simulated alert.

`internal/siem/packs` reads each rule from the vendor's own file with a small parser of the syntax the pack uses and evaluates it over every sample. A rule that fires on the wrong sample, or that uses syntax the parser doesn't know, fails the test. A change to the OCSF mapping that alters a sample fails it too.

That shows the logic of each rule. No vendor's engine ran it. Each pack's README says what that leaves unchecked.
