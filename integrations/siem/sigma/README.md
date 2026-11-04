# PantherClaw rules for Sigma

`rules/` holds one Sigma rule per detection, with log source `product: pantherclaw`, `service: ocsf`. Field names are the OCSF event's own, dotted for nesting.

## Use

Convert them for your SIEM with the Sigma tools you already use. You need a processing pipeline that maps this log source to where your PantherClaw events live. That pipeline is yours to write, as it depends on your backend. Sigma rules run nothing by themselves.

## Ingest

Sigma doesn't ingest anything. The rules expect each OCSF event stored as its own record, with the layout of the files in `../samples/`:

- Top-level fields such as `class_uid`, `activity_id`, `severity_id` and `status_id` are at the root.
- Nested fields are reached by their dotted path, for example `metadata.event_code`, `metadata.labels` and `unmapped.pantherclaw_uncertainty`.
- Numbers stay numbers and names are not renamed.

PantherClaw posts batches: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`. Splitting `data.events` into those records is the job of your SIEM's ingest. The Splunk and Elastic packs show one way, and the Sentinel and Wazuh packs say where their SIEMs can't. If your pipeline nests the event under a prefix, map the fields in your Sigma processing pipeline.

**The webhook signature is not verified** by any converted rule, and Sigma never sees it. `pclaw siem forward` verifies it before it writes the events to a file ([runbook](../../../docs/runbooks/siem-forwarder.md)).

## ATT&CK and ATLAS techniques

- Per rule: the first tag is the rule id; the rest are the `rules.yaml` ATT&CK Enterprise ids as Sigma tags, `attack.<tactic short name>` then `attack.t####[.###]`. A rule that names none has only its id tag.
- Per event, both frameworks: a backend reads the event as is. An alert carries them in `finding_info.attacks` and an incident in `finding_info_list[].attacks`, each entry with `technique.uid`, `sub_technique.uid` (when the id is a sub-technique), `tactic.uid` and `version` ("20.0" for ATT&CK, "ATLAS 2026.10" for ATLAS).

## What was not checked

- Whether `sigma check` accepts the tactic tag `attack.defense-impairment` (ATT&CK 20.0) has not been tried.

- `sigma check` has not run on these rules, and they have not been converted with any backend.
- A test reads the rules and evaluates the selection and filter over the samples, which checks the logic and not any conversion.
- `metadata.labels` is an array. Whether `|contains` matches an array element depends on the backend: try the filter on the `alert-high-simulated` sample after you convert.
- The rules are not in the SigmaHQ repository.
