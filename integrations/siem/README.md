# PantherClaw SIEM content packs

Detection content for six SIEMs, built on the OCSF 1.9 events PantherClaw exports. It is data written by the PantherClaw project, with no scripts and no third-party content, licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)). The SIEM export itself is a Business feature: see [docs/runbooks/siem-export.md](../../docs/runbooks/siem-export.md).

| Pack | Format |
|---|---|
| [splunk](splunk/README.md) | App directory: saved searches, a macro, a sourcetype |
| [sentinel](sentinel/README.md) | ARM template of scheduled analytics rules, table schema |
| [chronicle](chronicle/README.md) | YARA-L rules, a parser and the field map |
| [elastic](elastic/README.md) | Detection rule export, ingest pipeline, index template |
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

None of these SIEMs reads that as it stands. Run a small collector of your own in front of yours. It verifies the signature, refuses an old timestamp, drops duplicates on `metadata.uid`, then writes each entry of `data.events` to the SIEM as one event. No collector is included here. The rules assume each event arrives with its OCSF field names unchanged.

## Acting on what these rules find

A PantherClaw alert states how it knows what it says, in `unmapped.pantherclaw_uncertainty`: for example `OBSERVED`, `RULE_MATCH` or `INFERRED`. An inference is a reason to look, not proof. PantherClaw's own automations refuse to contain on an inferred alert. A SOAR or script of yours that acts on these exported events is outside PantherClaw's control, and that refusal doesn't reach it: read the field before you act.

## How the packs are tested

[samples/](samples/) holds golden OCSF events, byte for byte what the exporter writes for those fixtures. Some are events a rule must fire on, and others are near misses it must not: a low alert, a closed incident, a simulated alert.

`internal/siem/packs` reads each rule from the vendor's own file with a small parser of the syntax the pack uses and evaluates it over every sample. A rule that fires on the wrong sample, or that uses syntax the parser doesn't know, fails the test. A change to the OCSF mapping that alters a sample fails it too.

That shows the logic of each rule. No vendor's engine ran it. Each pack's README says what that leaves unchecked.
