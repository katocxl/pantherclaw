# PantherClaw rules for Google Security Operations (Chronicle)

There are three parts:

- `rules/` holds single-event YARA-L 2.0 rules over UDM.
- `parser/pantherclaw_ocsf.conf` is a custom parser that turns an export batch into one UDM event per OCSF event.
- `udm-map.json` says which OCSF field each UDM field the rules read comes from.

## Install

1. Create a custom log type and add `parser/pantherclaw_ocsf.conf` as its parser.
2. Get batches in as the next section says.
3. Upload the rules in `rules/`. A rule does nothing until you enable it.

## Ingest

PantherClaw posts each batch as one JSON body: `{"type":"pantherclaw.ocsf.batch","data":{…,"events":[…]}}`. Send each body to a webhook feed for the custom log type, as one log entry with no split delimiter.

The parser does the split. It drops anything that isn't a batch, loops over `data.events`, and writes one UDM event per entry. Each event's `ocsf_test` is `true` when the entry carries the `test` label.

**The webhook signature is not verified.** Chronicle doesn't read the Standard Webhooks headers, so anyone holding the feed's keys can write events that the rules will trust. A webhook feed also wants its API key and secret on each request, and the export sends neither. `pclaw siem forward` verifies the signature, but it writes the events to a file and adds no key ([runbook](../../../docs/runbooks/siem-forwarder.md)), so something you run must add them.

## What was not checked

This is the least proven pack. Read this before you rely on it.

- **The parser has never run.** It was written offline and no parser validator has seen it. Expect to fix it in the parser editor with `../samples/batch/batch.json`. Its loop syntax, the field removal between entries, and the `%{ev.…}` references inside the loop are the likeliest to need changes. A test checks only that the parser mentions every field `udm-map.json` names and that it has the batch loop.
- **The rules have not been compiled.** A test reads them and evaluates them over the samples through `udm-map.json`. That assumes the parser does what the map says.
- UDM's required fields for `GENERIC_EVENT` have not been checked against a live tenant.
- Whether Chronicle offers a built-in OCSF parser that would replace this one has not been checked.
