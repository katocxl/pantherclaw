# PantherClaw Hub content

The source of the items PantherClaw publishes through the Hub: policy templates, detection rules, range scenarios and automations. Everything here is data written by the PantherClaw project. There is no third-party code, and no item kind runs code. This directory is licensed under the Apache License, Version 2.0 ([LICENSE](LICENSE)).

## Layout

```
hub/items/<kind>/<slug>/item.yaml
hub/items/<kind>/<slug>/tests/
```

`<kind>` is `policy_template`, `detection_rule`, `range_scenario`, `tool_package` or `automation`. `item.yaml` holds `name`, `version`, `kind`, `title`, `summary` and `body`, where `body` is the kind's document. `pclaw-admin hub build` turns each `item.yaml` into a published `items/<sha256>.json` and lists it in a signed `index.jws`. Files in `tests/` are read by the checks and are not published.

| Kind | Body | What `tests/` holds |
|---|---|---|
| `policy_template` | `placeholders`, `rules` and `tests`, as a template's `policy.json` and `tests.json` | `values.yaml`: the example values and packages the rules are rendered and tested with |
| `detection_rule` | `content`: a custom rule document, id `org.…`, attention `ALERT` | `events.yaml`: more cases, in the rule's own test format |
| `range_scenario` | `file_name`, `scenario`: a `CX-90001`… file | `expect.yaml`: the step ids and the verdict the range must reach |
| `automation` | `automation_name`, `purpose`, `work_kind`, `definition` | `baseline.yaml`: the baseline cases the simulator runs |

## What installing does

Installing changes nothing that runs. A policy template becomes a draft policy version, a detection rule a draft custom rule and an automation a draft automation. Your usual tests, reviews and approvals then apply. A range scenario is only written to your machine: it is labelled customer-authored in reports and never enters an attested pack.

An automation carries no `review_by`, so that it can't go stale here. Set a review date in the draft before you validate it. Automations and detection rules keep their edition gates; a detection rule needs Business, and an automation Team.

Detection rules are alert-only and read decision records, never prompts or payloads. An empty result proves nothing: a template, rule or scenario here shows that one thing was checked, not that a deployment is safe.

## Checking

```
task hub:check
```

It runs the same validators the product uses: the policy gate with its mutation check, the detection compiler and its tests, the range scenario format, and automation validation and simulation.
